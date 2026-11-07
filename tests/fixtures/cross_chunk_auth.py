"""Events at original lines 100, 5000, and 9000; no generated attack results."""

from pathlib import Path

AUTH_LINES = {
    100: "2026-11-07T12:00:00Z Failed login from 192.168.1.5 for user admin.\n",
    101: "2026-11-07T12:01:00Z Failed login from 192.168.1.5 for user admin.\n",
    102: "2026-11-07T12:02:00Z Failed login from 192.168.1.5 for user admin.\n",
    4999: "2026-11-07T12:10:00Z Failed login from 192.168.1.5 for user admin.\n",
    5000: "2026-11-07T12:11:00Z Failed login from 192.168.1.5 for user admin.\n",
    9000: "2026-11-07T12:20:00Z Successful login from 192.168.1.5 for user admin.\n",
}
# Deliberate source-chunk fixture boundaries isolate correlation from tokenizer
# packing. Inference still re-packs/re-counts each source chunk before generation.
SOURCE_BOUNDARIES = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 8999, 9000]


def write_cross_chunk_log(path: Path, *, timestamps: bool = True) -> None:
    with path.open("w", encoding="utf-8", newline="") as file:
        for line in range(1, 9001):
            text = AUTH_LINES.get(line, f"INFO heartbeat record={line}\n")
            if not timestamps and line in AUTH_LINES:
                # Keep otherwise distinct failures so duplicate-message uncertainty
                # is tested separately from missing-clock correlation.
                text = text.split(" ", 1)[1].rstrip("\n") + f" attempt_record={line}\n"
            file.write(text)
