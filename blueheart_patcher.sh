#!/bin/sh
# BlueHeart01 Patcher — standalone shell launcher
# Usage:
#   ./blueheart_patcher.sh --audio PATH --bpf PATH
#   ./blueheart_patcher.sh --validate-only --audio PATH --bpf PATH
#
# The Python implementation is embedded below, so no separate .py file is required.

set -eu

# Resolve paths relative to the directory containing this script (normally the ROM root).
BLUEHEART_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export BLUEHEART_ROOT

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1 && python -c 'import sys; raise SystemExit(sys.version_info < (3, 8))' 2>/dev/null; then
    PYTHON=python
else
    echo "[ERROR] Python 3.8+ is required but was not found." >&2
    exit 127
fi

exec "$PYTHON" - "$@" <<'__BLUEHEART_PYTHON__'
#!/usr/bin/env python3
"""
BlueHeart01 Patcher
===================

Safely applies two source patches used by the BlueHeart01 Android tree:

1. audio_policy_configuration.xml
   Removes the custom "BT A2DP" device-port/route block declared for
   Dolby processing, allowing the normal Bluetooth audio policy to own
   Bluetooth A2DP routing.

2. sysmeminfo.cpp
   Adds an existence guard for:
       /sys/fs/bpf/map_gpuMem_gpu_mem_total_map
   before the BPF map is opened in:
       ReadPerProcessGpuMem()
       ReadProcessGpuUsageKb()

3. FrameworkResOverlay_GMS/res/values/config.xml
   Removes the exact Free Fire Max package allowlist entry:
       <item>com.dts.freefiremax</item>

Safety features
---------------
- Python syntax is self-checkable with: python3 -m py_compile ...
- Never partially writes a file: all replacements are preflighted first.
- Creates a .bak backup by default before changing each file.
- Uses atomic replacement when writing.
- Detects partial application instead of treating it as "already fixed".
- Preserves existing file permissions and, where practical, line endings.
- Fails closed when the expected source structure is ambiguous.
- Idempotent: running it again safely reports SKIP.

Usage
-----
python3 blueheart_patcher.py
python3 blueheart_patcher.py --audio path/to/audio_policy_configuration.xml \
    --bpf path/to/sysmeminfo.cpp

Useful options
--------------
--no-backup      Do not create .bak files.
--validate-only  Check whether each patch can be applied/already exists,
                 without modifying anything.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple


VERSION = "2.1"

AUDIO_COMMENT = "Custom Bluetooth Routes Declaration for Dolby Processing"
AUDIO_TAGS = ("BT A2DP Out", "BT A2DP Headphones", "BT A2DP Speaker")

AUDIO_PORT_BLOCK_RE = re.compile(
    rf"""
    ^[ \t]*<!--\s*{re.escape(AUDIO_COMMENT)}\s*-->[ \t]*\r?\n
    (?:
        ^[ \t]*<devicePort\b
        (?=[^>]*\btagName\s*=\s*["'](?:BT\ A2DP\ Out|BT\ A2DP\ Headphones|BT\ A2DP\ Speaker)["'])
        [^>]*>
        .*?
        ^[ \t]*</devicePort>[ \t]*\r?\n?
    ){{3}}
    """,
    re.IGNORECASE | re.MULTILINE | re.DOTALL | re.VERBOSE,
)

AUDIO_ROUTE_BLOCK_RE = re.compile(
    rf"""
    ^[ \t]*<!--\s*{re.escape(AUDIO_COMMENT)}\s*-->[ \t]*\r?\n
    (?:
        ^[ \t]*<route\b
        (?=[^>]*\btype\s*=\s*["']mix["'])
        (?=[^>]*\bsink\s*=\s*["'](?:BT\ A2DP\ Out|BT\ A2DP\ Headphones|BT\ A2DP\ Speaker)["'])
        [^>]*/>[ \t]*\r?\n?
    ){{3}}
    """,
    re.IGNORECASE | re.MULTILINE | re.DOTALL | re.VERBOSE,
)

AUDIO_PORT_TAG_RE = re.compile(
    r"<devicePort\b[^>]*\btagName\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE | re.DOTALL,
)
AUDIO_ROUTE_SINK_RE = re.compile(
    r"<route\b[^>]*\bsink\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE | re.DOTALL,
)

BPF_MAP_CALL = "bpf::BpfMapRO<uint64_t, uint64_t>(kBpfGpuMemTotalMap)"
BPF_GUARD_RE = re.compile(
    r"if\s*\(\s*access\s*\(\s*kBpfGpuMemTotalMap\s*,\s*F_OK\s*\)\s*!=\s*0\s*\)"
)

FREEFIRE_ITEM_RE = re.compile(
    r"^[ \t]*<item>\s*com\.dts\.freefiremax\s*</item>[ \t]*(?:\r?\n|$)",
    re.MULTILINE,
)

DEFAULT_ROOT = Path(os.environ.get("BLUEHEART_ROOT", os.getcwd()))
DEFAULT_AUDIO = str(DEFAULT_ROOT / "device/xiaomi/redwood/audio/audio_policy_configuration.xml")
DEFAULT_BPF = str(DEFAULT_ROOT / "system/memory/libmeminfo/sysmeminfo.cpp")
DEFAULT_FRAMEWORK = str(DEFAULT_ROOT / (
    "vendor/pixel/gms/common/proprietary/product/overlay/"
    "FrameworkResOverlay_GMS/res/values/config.xml"
))

FUNCTION_RE_TEMPLATE = r"""
(?P<header>
    \bbool\s+{name}\s*\(
        [^)]*
    \)\s*\{{
)
(?P<body>.*?)
(?P<else>
    ^[ \t]*\#else\b
)
"""


def _newline(text: str) -> str:
    """Return the dominant newline style, defaulting to LF."""
    crlf = text.count("\r\n")
    lf = text.count("\n")
    return "\r\n" if crlf and crlf >= max(1, lf // 2) else "\n"


def _read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return fh.read()


def _write_atomic(path: Path, content: str) -> None:
    """Atomically replace path while preserving its mode."""
    original_mode = stat.S_IMODE(path.stat().st_mode)
    parent = path.parent

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(parent),
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, original_mode)
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def _backup(path: Path) -> Path:
    """Create or refresh a simple sibling backup."""
    backup = Path(str(path) + ".bak")
    shutil.copy2(path, backup)
    return backup


def _status(tag: str, state: str, message: str) -> None:
    print(f"{tag:<8} {state:<7}: {message}")


def _audio_state(content: str) -> Tuple[int, int, int]:
    port_matches = list(AUDIO_PORT_BLOCK_RE.finditer(content))
    route_matches = list(AUDIO_ROUTE_BLOCK_RE.finditer(content))

    # A valid custom block must contain exactly the three expected endpoints.
    valid_ports = sum(
        1
        for match in port_matches
        if len(AUDIO_PORT_TAG_RE.findall(match.group(0))) == 3
        and set(AUDIO_PORT_TAG_RE.findall(match.group(0))) == set(AUDIO_TAGS)
    )
    valid_routes = sum(
        1
        for match in route_matches
        if len(AUDIO_ROUTE_SINK_RE.findall(match.group(0))) == 3
        and set(AUDIO_ROUTE_SINK_RE.findall(match.group(0))) == set(AUDIO_TAGS)
    )

    marker = content.count(AUDIO_COMMENT)
    return valid_ports, valid_routes, marker


def prepare_audio(path: Path) -> Tuple[bool, str, str]:
    """
    Return (success, new_content, result_message).

    success=True means the file is either already fixed or safely patchable.
    """
    if not path.is_file():
        return False, "", f"{path} not found"

    content = _read_text(path)
    ports, routes, marker = _audio_state(content)

    if ports == 0 and routes == 0 and marker == 0:
        return True, content, "already fixed (custom Dolby BT block absent)"

    if ports == 0 and routes == 0 and marker > 0:
        return (
            False,
            content,
            "custom Dolby comment exists, but the expected BT A2DP blocks "
            "cannot be matched safely",
        )

    if ports != 1 or routes != 1:
        return (
            False,
            content,
            f"ambiguous source: found {ports} device-port block(s) and "
            f"{routes} route block(s); refusing to patch",
        )

    # Replace only the two explicitly identified blocks.
    patched, n_ports = AUDIO_PORT_BLOCK_RE.subn("", content, count=1)
    patched, n_routes = AUDIO_ROUTE_BLOCK_RE.subn("", patched, count=1)

    if n_ports != 1 or n_routes != 1:
        # Defensive check; the counts above were already validated.
        return False, content, "internal replacement count check failed"

    remaining_ports, remaining_routes, _ = _audio_state(patched)
    if remaining_ports or remaining_routes:
        return False, content, "validation failed: BT A2DP custom block remains"

    return (
        True,
        patched,
        "removed the custom BT A2DP Dolby-processing ports/routes",
    )


def prepare_framework(path: Path) -> Tuple[bool, str, str]:
    """Remove exactly one Free Fire Max allowlist item safely."""
    if not path.is_file():
        return False, "", f"{path} not found"

    content = _read_text(path)
    matches = list(FREEFIRE_ITEM_RE.finditer(content))

    if not matches:
        return True, content, "already fixed (Free Fire Max allowlist entry absent)"

    if len(matches) != 1:
        return (
            False,
            content,
            f"ambiguous source: found {len(matches)} Free Fire Max allowlist entries; refusing to patch",
        )

    patched, count = FREEFIRE_ITEM_RE.subn("", content, count=1)
    if count != 1 or FREEFIRE_ITEM_RE.search(patched):
        return False, content, "validation failed: Free Fire Max allowlist entry remains"

    return True, patched, "removed <item>com.dts.freefiremax</item> from the GMS framework overlay"


def _find_function_body(content: str, name: str) -> Optional[re.Match[str]]:
    pattern = re.compile(
        FUNCTION_RE_TEMPLATE.format(name=re.escape(name)),
        re.MULTILINE | re.DOTALL | re.VERBOSE,
    )
    matches = list(pattern.finditer(content))
    if len(matches) != 1:
        return None
    return matches[0]


def _guard_for(function_name: str, newline: str, body: str) -> str:
    if function_name == "ReadPerProcessGpuMem":
        # Keep the user's original requested semantics: if the kernel BPF map
        # file does not exist, report no GPU entries rather than failing.
        return (
            f"    if (access(kBpfGpuMemTotalMap, F_OK) != 0) {{{newline}"
            f"        return true;{newline}"
            f"    }}{newline}{newline}"
        )

    if function_name == "ReadProcessGpuUsageKb":
        return (
            f"    if (access(kBpfGpuMemTotalMap, F_OK) != 0) {{{newline}"
            f"        if (size) *size = 0;{newline}"
            f"        return true;{newline}"
            f"    }}{newline}{newline}"
        )

    raise ValueError(f"Unsupported function: {function_name}")


def _insert_guard(
    content: str,
    function_name: str,
    newline: str,
) -> Tuple[bool, str, str]:
    match = _find_function_body(content, function_name)
    if match is None:
        return False, content, f"{function_name}() definition not found uniquely"

    body = match.group("body")

    if BPF_GUARD_RE.search(body):
        return True, content, f"{function_name}() guard already present"

    map_pos = body.find(BPF_MAP_CALL)
    if map_pos < 0:
        return False, content, f"{function_name}() BpfMapRO call not found"

    # Insert immediately before the map construction line while preserving
    # indentation already present in the source.
    line_start = body.rfind("\n", 0, map_pos) + 1
    insertion = _guard_for(function_name, newline, body)
    new_body = body[:line_start] + insertion + body[line_start:]

    start, end = match.span("body")
    patched = content[:start] + new_body + content[end:]
    return True, patched, f"patched {function_name}()"


def _ensure_unistd_include(content: str, newline: str) -> Tuple[bool, str]:
    """Add <unistd.h> only when access()/F_OK is used but the header is absent."""
    if re.search(r"^\s*#\s*include\s*[<\"]unistd\.h[>\"]", content, re.MULTILINE):
        return False, content

    if not re.search(r"\baccess\s*\(", content) or not re.search(r"\bF_OK\b", content):
        return False, content

    include_matches = list(re.finditer(r"^\s*#\s*include\b.*$", content, re.MULTILINE))
    if not include_matches:
        return False, content

    last = include_matches[-1]
    line_end = content.find("\n", last.end())
    if line_end < 0:
        line_end = len(content)
    else:
        line_end += 1

    patched = (
        content[:line_end]
        + f"#include <unistd.h>{newline}"
        + content[line_end:]
    )
    return True, patched


def prepare_bpf(path: Path) -> Tuple[bool, str, str]:
    if not path.is_file():
        return False, "", f"{path} not found"

    content = _read_text(path)
    newline = _newline(content)

    functions = ("ReadPerProcessGpuMem", "ReadProcessGpuUsageKb")
    working = content
    changed = False

    for name in functions:
        ok, candidate, message = _insert_guard(working, name, newline)
        if not ok:
            return False, content, message
        if candidate != working:
            changed = True
        working = candidate

    # Make sure both guards exist after the transformations.
    final_matches = list(
        re.finditer(BPF_GUARD_RE, working)
    )
    if len(final_matches) < 2:
        return False, content, "validation failed: fewer than two BPF guards found"

    include_added, working = _ensure_unistd_include(working, newline)
    changed = changed or include_added

    if not changed:
        # Both target guards were already present.
        return True, content, "already fixed (both BPF guards present)"

    extra = "; added <unistd.h>" if include_added else ""
    return True, working, f"added BPF map-existence guards{extra}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BlueHeart01 patcher — BT audio, sysmeminfo BPF, and Free Fire Max allowlist fixes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--audio",
        default=DEFAULT_AUDIO,
        metavar="PATH",
        help="path to audio_policy_configuration.xml (default: device/xiaomi/redwood/audio/audio_policy_configuration.xml)",
    )
    parser.add_argument(
        "--bpf",
        default=DEFAULT_BPF,
        metavar="PATH",
        help="path to sysmeminfo.cpp (default: system/memory/libmeminfo/sysmeminfo.cpp)",
    )
    parser.add_argument(
        "--framework",
        default=DEFAULT_FRAMEWORK,
        metavar="PATH",
        help="path to FrameworkResOverlay_GMS config.xml (default: vendor/pixel/gms/common/proprietary/product/overlay/FrameworkResOverlay_GMS/res/values/config.xml)",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="do not create .bak backups",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="check applicability without modifying files",
    )
    args = parser.parse_args()

    audio = Path(args.audio).expanduser()
    bpf = Path(args.bpf).expanduser()
    framework = Path(args.framework).expanduser()

    print("=" * 72)
    print(f" BlueHeart01 Patcher v{VERSION}")
    print("=" * 72)
    print(f" Audio : {audio}")
    print(f" BPF   : {bpf}")
    print(f" GMS   : {framework}")
    print(f" Mode  : {'VALIDATE ONLY' if args.validate_only else 'PATCH'}")
    print(f" Backup: {'OFF' if args.no_backup else 'ON'}")
    print("-" * 72)

    # Preflight both files before touching either one. This prevents the
    # common failure mode where audio gets modified but BPF fails halfway.
    prepared = []
    for path, tag, fn in (
        (audio, "[audio]", prepare_audio),
        (bpf, "[bpf]", prepare_bpf),
        (framework, "[gms]", prepare_framework),
    ):
        try:
            ok, new_content, message = fn(path)
        except (OSError, UnicodeError) as exc:
            _status(tag, "ERROR", f"could not read {path}: {exc}")
            return 1

        prepared.append((path, tag, new_content, message, ok))
        if not ok:
            _status(tag, "ERROR", message)

    if not all(item[4] for item in prepared):
        print("=" * 72)
        print(" Refusing to modify files because preflight validation failed.")
        return 1

    if args.validate_only:
        for path, tag, new_content, message, _ in prepared:
            current = _read_text(path)
            _status(
                tag,
                "SKIP" if current == new_content else "CHECK",
                message,
            )
        print("=" * 72)
        print(" Validation complete. No files were modified.")
        return 0

    # Apply only after both files have passed preflight.
    failures = 0
    for path, tag, new_content, message, _ in prepared:
        current = _read_text(path)
        if current == new_content:
            _status(tag, "SKIP", message)
            continue
        try:
            backup = None if args.no_backup else _backup(path)
            _write_atomic(path, new_content)
            if backup:
                _status(tag, "BACKUP", str(backup))
            _status(tag, "OK", f"{path} — {message}")
        except OSError as exc:
            _status(tag, "ERROR", f"write failed for {path}: {exc}")
            failures += 1

    print("=" * 72)
    if failures:
        print(f" Completed with {failures} write failure(s).")
        return 1

    print(" All requested patches completed successfully.")
    print(" Run the script again to verify idempotency; already-fixed files will SKIP.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

__BLUEHEART_PYTHON__
