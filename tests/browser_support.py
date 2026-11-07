"""Small optional Chrome DevTools driver. Uses an installed browser; no downloads.

Only test code speaks CDP over a loopback WebSocket. This avoids introducing Node,
Playwright, Selenium or a browser runtime into the application/environment.
"""

import base64
import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx


class Browser:
    def __init__(self, directory: Path) -> None:
        executable = os.environ.get("CHROME_PATH", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        if not Path(executable).is_file():
            raise RuntimeError("Set CHROME_PATH to an existing Chrome/Chromium executable.")
        self.directory = directory
        self.process = subprocess.Popen([
            executable, "--headless=new", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
            f"--user-data-dir={directory / 'profile'}", "--no-first-run", "--no-default-browser-check",
            "--disable-background-networking", "--disable-extensions", "--disable-sync", "--disable-component-update",
            "--disable-default-apps", "--metrics-recording-only", "--password-store=basic",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1", "about:blank",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.socket = None
        self.buffer = bytearray()
        self.serial = 0
        self.exceptions: list[dict] = []
        try:
            port_file = directory / "profile" / "DevToolsActivePort"
            deadline = time.monotonic() + 15
            while not port_file.exists():
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Installed Chrome could not start its local test profile.")
                time.sleep(0.03)
            port = int(port_file.read_text().splitlines()[0])
            with httpx.Client(trust_env=False, timeout=10) as client:
                target = client.put(f"http://127.0.0.1:{port}/json/new?about:blank").json()
            address = urlsplit(target["webSocketDebuggerUrl"])
            self.socket = socket.create_connection((address.hostname, address.port), timeout=15)
            key = base64.b64encode(os.urandom(16)).decode()
            self.socket.sendall((f"GET {address.path} HTTP/1.1\r\nHost: {address.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
            handshake = bytearray()
            while b"\r\n\r\n" not in handshake:
                handshake.extend(self.socket.recv(4096))
                if len(handshake) > 65536:
                    raise RuntimeError("Invalid local browser handshake.")
            headers, remaining = handshake.split(b"\r\n\r\n", 1)
            if b" 101 " not in headers.split(b"\r\n", 1)[0]:
                raise RuntimeError("Local browser rejected the DevTools connection.")
            self.buffer.extend(remaining)
            self.call("Runtime.enable")
            self.call("Page.enable")
            self.call("Browser.setDownloadBehavior", {"behavior": "allow", "downloadPath": str(directory)})
        except BaseException:
            self.close()
            raise

    def _read(self, length: int) -> bytes:
        while len(self.buffer) < length:
            data = self.socket.recv(max(4096, length - len(self.buffer)))
            if not data:
                raise RuntimeError("Local browser connection closed.")
            self.buffer.extend(data)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    def _send(self, data: bytes, opcode: int = 1) -> None:
        length = len(data)
        header = bytes([0x80 | opcode])
        if length < 126:
            header += bytes([0x80 | length])
        elif length < 65536:
            header += bytes([0xFE]) + struct.pack("!H", length)
        else:
            header += bytes([0xFF]) + struct.pack("!Q", length)
        mask = os.urandom(4)
        self.socket.sendall(header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(data)))

    def _receive(self) -> dict:
        message = bytearray()
        while True:
            first, second = self._read(2)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read(8))[0]
            if length > 20 * 1024 * 1024:
                raise RuntimeError("Unexpectedly large local browser frame.")
            mask = self._read(4) if second & 0x80 else None
            data = self._read(length)
            if mask:
                data = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
            opcode = first & 0xF
            if opcode == 8:
                raise RuntimeError("Local browser closed DevTools.")
            if opcode == 9:
                self._send(data, 10)
                continue
            if opcode == 10:
                continue
            message.extend(data)
            if first & 0x80:
                return json.loads(message)

    def call(self, method: str, parameters: dict | None = None) -> dict:
        self.serial += 1
        serial = self.serial
        self._send(json.dumps({"id": serial, "method": method, "params": parameters or {}}).encode())
        while True:
            result = self._receive()
            if result.get("method") == "Runtime.exceptionThrown":
                self.exceptions.append(result["params"])
            if result.get("id") == serial:
                if "error" in result:
                    raise AssertionError(result["error"])
                return result.get("result", {})

    def evaluate(self, expression: str):
        result = self.call("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in result:
            raise AssertionError(result["exceptionDetails"])
        return result["result"].get("value")

    def wait(self, expression: str, timeout: float = 15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.evaluate(expression)
            if result:
                return result
            time.sleep(0.03)
        raise AssertionError(f"Browser condition timed out: {expression}")

    def navigate(self, url: str) -> None:
        self.call("Page.navigate", {"url": url})
        self.wait("document.readyState === 'complete' && !!document.querySelector('#upload-button')")

    def click(self, selector: str) -> None:
        self.evaluate(f"document.querySelector({json.dumps(selector)}).click()")

    def upload(self, path: Path) -> None:
        root = self.call("DOM.getDocument")["root"]["nodeId"]
        target = self.call("DOM.querySelector", {"nodeId": root, "selector": "#log-file"})["nodeId"]
        self.call("DOM.setFileInputFiles", {"nodeId": target, "files": [str(path)]})

    def screenshot(self, path: Path, width: int = 1440, height: int = 1150) -> None:
        self.call("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": width < 600})
        self.evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
        result = self.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(result["data"]))

    def close(self) -> None:
        if self.socket:
            self.socket.close()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
