"""Strict single-file multipart streaming with incremental UTF-8 validation."""

import codecs
import hashlib
import os
from pathlib import Path

from fastapi import Request
from python_multipart import MultipartParser
from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import parse_options_header
from starlette.concurrency import run_in_threadpool

from app.errors import AppError

READ_BYTES = 64 * 1024
HEADER_BYTES = 8192
ENVELOPE_BYTES = 16 * 1024


class UploadReceiver:
    def __init__(self, path: Path, max_bytes: int, boundary: bytes) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.size = 0
        self.filename = ""
        self.hash = hashlib.sha256()
        self.decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.has_text = False
        self.parts = 0
        self.finished = False
        self.part_finished = False
        self.headers: dict[bytes, bytes] = {}
        self.header_name = bytearray()
        self.header_value = bytearray()
        self.header_size = 0
        self.file = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        self.parser = MultipartParser(boundary, {
            "on_part_begin": self.part_begin,
            "on_header_field": self.header_field,
            "on_header_value": self.header_data,
            "on_header_end": self.header_end,
            "on_headers_finished": self.headers_finished,
            "on_part_data": self.part_data,
            "on_part_end": self.part_end,
            "on_end": self.end,
        })

    def part_begin(self) -> None:
        self.parts += 1
        if self.parts > 1:
            raise AppError(400, "invalid_multipart", "Send exactly one file in the 'file' field.")

    def _header(self, target: bytearray, data: bytes, start: int, end: int) -> None:
        self.header_size += end - start
        if self.header_size > HEADER_BYTES:
            raise AppError(400, "invalid_multipart", "Multipart headers are too large.")
        target.extend(data[start:end])

    def header_field(self, data: bytes, start: int, end: int) -> None:
        self._header(self.header_name, data, start, end)

    def header_data(self, data: bytes, start: int, end: int) -> None:
        self._header(self.header_value, data, start, end)

    def header_end(self) -> None:
        name = bytes(self.header_name).lower()
        if name in self.headers:
            raise AppError(400, "invalid_multipart", "Duplicate multipart headers are not accepted.")
        self.headers[name] = bytes(self.header_value)
        self.header_name.clear()
        self.header_value.clear()

    def headers_finished(self) -> None:
        disposition, options = parse_options_header(self.headers.get(b"content-disposition", b""))
        if disposition != b"form-data" or options.get(b"name") != b"file" or b"filename" not in options:
            raise AppError(400, "invalid_multipart", "Send exactly one file in the 'file' field.")
        try:
            filename = options[b"filename"].decode("utf-8")
        except UnicodeDecodeError:
            raise AppError(400, "invalid_filename", "The filename must use UTF-8.") from None
        # Display metadata only. Filesystem paths always use the server-generated UUID.
        self.filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        if not self.filename or len(self.filename) > 255 or any(ord(c) < 32 for c in self.filename):
            raise AppError(400, "invalid_filename", "The filename is invalid.")
        if Path(self.filename).suffix.lower() not in {".log", ".txt"}:
            raise AppError(415, "unsupported_file_type", "Only .log and .txt files are accepted.")
        mime = self.headers.get(b"content-type", b"application/octet-stream").split(b";", 1)[0].strip().lower()
        if mime not in {b"text/plain", b"text/x-log", b"application/octet-stream"}:
            raise AppError(415, "unsupported_file_type", "The declared file content type is unsupported.")

    def validate_text(self, data: bytes, *, final: bool = False) -> None:
        try:
            text = self.decoder.decode(data, final=final)
        except UnicodeDecodeError:
            raise AppError(415, "binary_file", "Upload a UTF-8 text log, not binary data.") from None
        if any((ord(c) < 32 and c not in "\t\r\n") or 127 <= ord(c) <= 159 for c in text):
            raise AppError(415, "binary_file", "Binary or unsupported control characters were found.")
        if text.strip("\ufeff \t\r\n"):
            self.has_text = True

    def part_data(self, data: bytes, start: int, end: int) -> None:
        piece = data[start:end]
        self.size += len(piece)
        if self.size > self.max_bytes:
            raise AppError(413, "file_too_large", "The file exceeds MAX_UPLOAD_BYTES.")
        self.validate_text(piece)
        self.hash.update(piece)
        self.file.write(piece)

    def part_end(self) -> None:
        self.validate_text(b"", final=True)
        self.part_finished = True

    def end(self) -> None:
        self.finished = True

    def feed(self, data: bytes) -> None:
        self.parser.write(data)

    def finish(self) -> None:
        self.parser.finalize()
        if not self.finished or not self.part_finished or self.parts != 1:
            raise AppError(400, "invalid_multipart", "The multipart upload is missing or incomplete.")
        if not self.size or not self.has_text:
            raise AppError(400, "empty_file", "The file contains no log text.")
        self.file.flush()
        os.fsync(self.file.fileno())


def multipart_boundary(request: Request, max_bytes: int) -> bytes:
    mime, options = parse_options_header(request.headers.get("content-type", ""))
    boundary = options.get(b"boundary", b"")
    if mime != b"multipart/form-data" or not 1 <= len(boundary) <= 200:
        raise AppError(400, "invalid_multipart", "Use multipart/form-data with one 'file' field.")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError:
            raise AppError(400, "invalid_multipart", "Invalid Content-Length header.") from None
        if length < 0:
            raise AppError(400, "invalid_multipart", "Invalid Content-Length header.")
        if length > max_bytes + ENVELOPE_BYTES:
            raise AppError(413, "file_too_large", "The upload exceeds the configured size limit.")
    return boundary


async def receive_upload(request: Request, receiver: UploadReceiver) -> None:
    received = 0
    try:
        async for frame in request.stream():
            received += len(frame)
            if received > receiver.max_bytes + ENVELOPE_BYTES:
                raise AppError(413, "file_too_large", "The upload exceeds the configured size limit.")
            for offset in range(0, len(frame), READ_BYTES):
                await run_in_threadpool(receiver.feed, frame[offset:offset + READ_BYTES])
        await run_in_threadpool(receiver.finish)
    except MultipartParseError:
        raise AppError(400, "invalid_multipart", "The multipart upload is malformed.") from None
    finally:
        await run_in_threadpool(receiver.file.close)
