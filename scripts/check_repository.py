#!/usr/bin/env python3
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_FILES = {
    "IcmpHandler.py",
    "IpHandler.py",
    "LoggingSystem.py",
    "Main.py",
    "NATmonitor.py",
    "SendRecieve.py",
    "TcpHandler.py",
    "UdpHandler.py",
}
PYTHON_FILES = {"src/" + name for name in PYTHON_FILES}
PROJECT_FILES = PYTHON_FILES | {"scripts/NATscript.sh", "data/ICMPTypes.txt"}
REPOSITORY_FILES = PROJECT_FILES | {
    ".gitattributes",
    ".gitignore",
    "Makefile",
    "README.md",
    "docs/project-report.pdf",
    "scripts/check_repository.py",
    "tests/test_helpers.py",
    "tests/test_packets.py",
    "docker/Dockerfile",
    ".dockerignore",
}


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


missing = sorted(name for name in PROJECT_FILES if not (ROOT / name).is_file())
if missing:
    fail("Missing required NAT project files: " + ", ".join(missing))

actual_files = {
    path.relative_to(ROOT).as_posix()
    for path in ROOT.rglob("*")
    if path.is_file() and ".git" not in path.parts
}
unexpected = sorted(actual_files - REPOSITORY_FILES)
if unexpected:
    fail("Unapproved extra project files: " + ", ".join(unexpected))

for name in PYTHON_FILES:
    source = (ROOT / name).read_text(encoding="utf-8", errors="strict")
    if "Created By: Kobie Hazon" not in source:
        fail(f"Missing authorship header: {name}")

combined_source = "\n".join(
    (ROOT / name).read_text(encoding="utf-8") for name in PROJECT_FILES
)
for marker in [
    "class ARPCache",
    "class TcpNat",
    "class UdpNat",
    "socket.AF_PACKET",
    "iptables",
    "src/Main.py",
]:
    if marker not in combined_source:
        fail(f"Missing expected NAT implementation marker: {marker}")

for path in ROOT.rglob("*"):
    if ".git" in path.parts or not path.is_file():
        continue
    rel = path.relative_to(ROOT).as_posix()
    if any(part.startswith("._") for part in path.parts) or path.name in {
        ".DS_Store",
        "Thumbs.db",
    }:
        fail(f"Metadata file should not be staged: {rel}")
    if path.suffix.lower() in {".pyc", ".pyo", ".doc", ".docx"}:
        fail(f"Generated or private artifact should not be staged: {rel}")

text_files = [
    path
    for path in ROOT.rglob("*")
    if path.is_file()
    and ".git" not in path.parts
    and path.suffix.lower() in {".py", ".sh", ".txt", ".md", ""}
]
text = "\n".join(
    path.read_text(encoding="utf-8", errors="ignore") for path in text_files
)
private_markers = [
    "".join(["208", "234", "161"]),  # noqa: FLY002 - avoid matching this checker
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "C:" + "\\" + "Users",
]
if (
    any(marker in text for marker in private_markers)
    or re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
    or re.search(r"(?<![A-Za-z0-9])\d{9}(?![A-Za-z0-9])", text)
):
    fail("Privacy or machine-path marker found in tracked text")

print("Python NAT router static checks passed.")
