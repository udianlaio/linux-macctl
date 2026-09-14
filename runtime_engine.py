#!/usr/bin/env python3
"""Pure local execution primitives used by Linux-macctl/macctl.

Kept independent of /etc/macctl and SSH state so output-cap and timeout
semantics can be tested deterministically on Linux/GitHub runners.

R0 remote-execution hardening guarantees two things that the old
subprocess.run implementation did not: output is spooled to an anonymous
temporary file instead of being accumulated without bound in memory, and a
timeout terminates the whole local process group so helper descendants such as
rsync -> ssh cannot outlive the caller.
"""
from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from typing import BinaryIO, Sequence


def _read_bounded_capture(capture: BinaryIO, cap: int) -> tuple[str, bool, int]:
    cap_i = max(0, int(cap))
    capture.flush()
    total_bytes = int(os.fstat(capture.fileno()).st_size)
    capture.seek(0)
    data = capture.read(cap_i)
    truncated = total_bytes > cap_i
    text = data.decode("utf-8", "replace").rstrip("\n")
    if truncated:
        text += f"\n[MACCTL_OUTPUT_TRUNCATED bytes={total_bytes} cap={cap_i}]"
    return text, truncated, total_bytes


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Best-effort hard stop for the isolated local process group."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        return
    except ProcessLookupError:
        return
    except (AttributeError, PermissionError, OSError):
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass


def bounded_run(
    argv: Sequence[str],
    *,
    timeout: float,
    cap: int,
    input_bytes: bytes | None = None,
) -> dict:
    t0 = time.perf_counter()
    with tempfile.TemporaryFile(mode="w+b") as capture:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=capture,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        timed_out = False
        try:
            proc.communicate(input=input_bytes if input_bytes is not None else b"", timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(proc)
            try:
                proc.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                # The direct process should already be gone after SIGKILL; this
                # fallback exists only for unusual platform/process semantics.
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                proc.communicate()

        text, truncated, total_bytes = _read_bounded_capture(capture, int(cap))
        result = {
            "rc": 124 if timed_out else proc.returncode,
            "output": text,
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
            "truncated": truncated,
            "bytes": total_bytes,
        }
        if timed_out:
            result["error"] = "timeout"
        return result
