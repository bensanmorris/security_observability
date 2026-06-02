#!/usr/bin/env python3
"""
Java cert-agent deployer.

Monitors running JVM processes and attaches the cert-agent dynamically
via the JVM Attach API (using jattach). For JVMs that reject dynamic
attach, prints the static -javaagent flag needed on next restart.

Requires: jattach (https://github.com/jattach/jattach)

Usage:
  python3 java_agent_deployer.py [--agent-jar PATH] [--native-lib PATH]
                                 [--jattach PATH] [--interval SECONDS]
                                 [--once]
"""

import argparse
import logging
import os
import subprocess
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

DEFAULT_AGENT_JAR  = "/opt/cert-agent/cert-agent.jar"
DEFAULT_NATIVE_LIB = "/opt/cert-agent/libcert_agent_stub.so"
DEFAULT_JATTACH    = "jattach"
DEFAULT_INTERVAL   = 30  # seconds between scans


def find_java_pids() -> set[int]:
    """Return the set of PIDs for running JVM processes."""
    pids = set()
    try:
        proc_dir = "/proc"
        for entry in os.listdir(proc_dir):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                continue
            if os.path.basename(exe) in ("java", "java11", "java17", "java21"):
                pids.add(pid)
    except OSError as e:
        log.warning("Could not scan /proc: %s", e)
    return pids


def attach_agent(pid: int, agent_jar: str, native_lib: str, jattach: str) -> bool:
    """
    Try to load the cert-agent into a running JVM via jattach.
    Returns True on success, False if attach failed.
    """
    agent_arg = f"{agent_jar}={native_lib}"
    cmd = [jattach, str(pid), "load", "instrument", "false", agent_arg]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            log.info("Attached cert-agent to PID %d", pid)
            return True
        else:
            log.debug(
                "jattach failed for PID %d (exit %d): %s",
                pid, result.returncode, (result.stderr or result.stdout).strip(),
            )
            return False
    except FileNotFoundError:
        log.error("jattach not found at '%s' — install it from https://github.com/jattach/jattach", jattach)
        return False
    except subprocess.TimeoutExpired:
        log.warning("jattach timed out for PID %d", pid)
        return False


def print_static_instructions(pid: int, agent_jar: str, native_lib: str) -> None:
    """Print the -javaagent flag needed for static injection on next restart."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
    except OSError:
        cmdline = f"<PID {pid}>"

    log.warning(
        "Could not dynamically attach to PID %d (%s).\n"
        "  Add this flag to the JVM command line on next restart:\n"
        "    -javaagent:%s=%s",
        pid, cmdline, agent_jar, native_lib,
    )


def scan_and_attach(
    seen_pids: set[int],
    agent_jar: str,
    native_lib: str,
    jattach: str,
) -> set[int]:
    """Scan for new Java processes and attempt attachment. Returns updated seen set."""
    current_pids = find_java_pids()
    new_pids = current_pids - seen_pids

    for pid in sorted(new_pids):
        log.info("New JVM detected: PID %d", pid)
        success = attach_agent(pid, agent_jar, native_lib, jattach)
        if not success:
            print_static_instructions(pid, agent_jar, native_lib)

    # Remove PIDs that are no longer running.
    still_running = current_pids & seen_pids
    gone = seen_pids - current_pids
    if gone:
        log.debug("JVMs exited: %s", gone)

    return still_running | new_pids


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--agent-jar",  default=DEFAULT_AGENT_JAR,
                        help="Path to cert-agent.jar (default: %(default)s)")
    parser.add_argument("--native-lib", default=DEFAULT_NATIVE_LIB,
                        help="Path to libcert_agent_stub.so (default: %(default)s)")
    parser.add_argument("--jattach",    default=DEFAULT_JATTACH,
                        help="jattach binary name or path (default: %(default)s)")
    parser.add_argument("--interval",   type=int, default=DEFAULT_INTERVAL,
                        help="Seconds between /proc scans (default: %(default)s)")
    parser.add_argument("--once",       action="store_true",
                        help="Scan once and exit (useful for testing)")
    args = parser.parse_args()

    if not os.path.isfile(args.agent_jar):
        log.error("Agent JAR not found: %s", args.agent_jar)
        sys.exit(1)
    if not os.path.isfile(args.native_lib):
        log.error("Native library not found: %s", args.native_lib)
        sys.exit(1)

    log.info("cert-agent deployer starting")
    log.info("  agent JAR:  %s", args.agent_jar)
    log.info("  native lib: %s", args.native_lib)
    log.info("  jattach:    %s", args.jattach)

    seen_pids: set[int] = set()

    if args.once:
        scan_and_attach(seen_pids, args.agent_jar, args.native_lib, args.jattach)
        return

    while True:
        seen_pids = scan_and_attach(seen_pids, args.agent_jar, args.native_lib, args.jattach)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
