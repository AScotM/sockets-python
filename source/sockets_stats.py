
#!/usr/bin/env python3

import argparse
import csv
import datetime
import io
import json
import os
import resource
import signal
import socket
import sys
import time

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


VERSION = "2.0.0"

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

SOCKET_TABLES = {
    "tcp": ("net/tcp", "TCP", 4),
    "tcp6": ("net/tcp6", "TCP", 6),
    "udp": ("net/udp", "UDP", 4),
    "udp6": ("net/udp6", "UDP", 6),
    "udplite": ("net/udplite", "UDPLITE", 4),
    "udplite6": ("net/udplite6", "UDPLITE", 6),
    "raw": ("net/raw", "RAW", 4),
    "raw6": ("net/raw6", "RAW", 6),
}

MEMORY_FIELDS = {"mem", "memory"}

IMPORTANT_COUNTERS = {
    "Tcp": [
        "ActiveOpens",
        "PassiveOpens",
        "AttemptFails",
        "EstabResets",
        "InSegs",
        "OutSegs",
        "RetransSegs",
        "InErrs",
        "OutRsts",
    ],
    "Udp": [
        "InDatagrams",
        "NoPorts",
        "InErrors",
        "OutDatagrams",
        "RcvbufErrors",
        "SndbufErrors",
    ],
    "Ip": [
        "InReceives",
        "InDiscards",
        "InDelivers",
        "OutRequests",
        "OutDiscards",
    ],
    "TcpExt": [
        "ListenOverflows",
        "ListenDrops",
        "TCPTimeouts",
        "TCPSynRetrans",
        "TCPLossProbes",
        "TCPBacklogDrop",
        "TCPMemoryPressures",
    ],
}


class SocketStatsError(Exception):
    pass


@dataclass
class Config:
    proc_root: Path
    output_format: str
    output_file: str | None
    extended: bool
    processes: bool
    process_limit: int
    watch: bool
    interval: float
    count: int
    performance: bool
    quiet: bool
    verbose: bool
    threshold_tcp: int | None
    threshold_established: int | None
    threshold_timewait: int | None
    threshold_orphan: int | None
    threshold_retrans: float | None
    max_file_bytes: int


class ProcReader:
    def __init__(self, root: Path, max_bytes: int, verbose: bool):
        self.root = root
        self.max_bytes = max_bytes
        self.verbose = verbose
        self.warnings = []

    def read(self, relative: str, optional: bool = True) -> list[str]:
        path = self.root / relative

        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                lines = []
                size = 0

                for line in stream:
                    size += len(line.encode("utf-8"))

                    if size > self.max_bytes:
                        raise SocketStatsError(
                            f"Read limit exceeded: {path}"
                        )

                    lines.append(line.rstrip("\r\n"))

                return lines

        except FileNotFoundError:
            if not optional:
                raise SocketStatsError(f"Required file missing: {path}")

            if self.verbose:
                self.warnings.append(f"Optional file missing: {path}")

            return []

        except PermissionError:
            self.warnings.append(f"Permission denied: {path}")
            return []

        except OSError as exc:
            self.warnings.append(f"Cannot read {path}: {exc}")
            return []


def parse_pairs(tokens: list[str]) -> dict[str, int]:
    result = {}

    for index in range(0, len(tokens) - 1, 2):
        key = tokens[index]

        try:
            result[key] = int(tokens[index + 1])
        except ValueError:
            continue

    return result


def parse_sockstat(lines: list[str]) -> dict[str, Any]:
    result = {}

    for line in lines:
        parts = line.split()

        if len(parts) < 3:
            continue

        section = parts[0].rstrip(":").lower()
        result[section] = parse_pairs(parts[1:])

    return result


def parse_mib(lines: list[str]) -> dict[str, dict[str, int]]:
    result = defaultdict(dict)
    pending = {}

    for line in lines:
        parts = line.split()

        if len(parts) < 2:
            continue

        section = parts[0].rstrip(":")
        fields = parts[1:]

        if section not in pending:
            pending[section] = fields
            continue

        headers = pending.pop(section)

        if len(headers) != len(fields):
            continue

        for key, value in zip(headers, fields):
            try:
                result[section][key] = int(value)
            except ValueError:
                continue

    return dict(result)


def decode_ipv4(value: str) -> str:
    try:
        return socket.inet_ntop(
            socket.AF_INET,
            bytes.fromhex(value)[::-1],
        )
    except (ValueError, OSError):
        return value


def decode_ipv6(value: str) -> str:
    try:
        raw = bytes.fromhex(value)

        if len(raw) != 16:
            return value

        reordered = b"".join(
            raw[index:index + 4][::-1]
            for index in range(0, 16, 4)
        )

        return socket.inet_ntop(socket.AF_INET6, reordered)

    except (ValueError, OSError):
        return value


def decode_endpoint(value: str, family: int) -> str:
    try:
        address, port_hex = value.rsplit(":", 1)
        port = int(port_hex, 16)

        if family == 6:
            return f"[{decode_ipv6(address)}]:{port}"

        return f"{decode_ipv4(address)}:{port}"

    except (ValueError, IndexError):
        return value


def parse_inet_table(
    lines: list[str],
    protocol: str,
    family: int,
) -> dict[str, Any]:
    states = Counter()
    records = []
    inodes = set()
    total = 0

    for line in lines[1:]:
        parts = line.split()

        if len(parts) < 10:
            continue

        total += 1

        state_code = parts[3].upper()
        state = TCP_STATES.get(state_code, state_code)

        if protocol == "TCP":
            states[state] += 1

        try:
            inode = int(parts[9])
        except ValueError:
            inode = 0

        if inode:
            inodes.add(inode)

        records.append({
            "protocol": protocol,
            "family": family,
            "local": decode_endpoint(parts[1], family),
            "remote": decode_endpoint(parts[2], family),
            "state": state if protocol == "TCP" else state_code,
            "inode": inode,
        })

    return {
        "count": total,
        "states": dict(sorted(states.items())),
        "inodes": inodes,
        "records": records,
    }


def parse_unix(lines: list[str]) -> dict[str, Any]:
    types = Counter()
    states = Counter()
    paths = Counter()
    inodes = set()
    count = 0

    type_names = {
        "0001": "STREAM",
        "0002": "DGRAM",
        "0005": "SEQPACKET",
    }

    state_names = {
        "01": "UNCONNECTED",
        "02": "CONNECTING",
        "03": "CONNECTED",
        "04": "DISCONNECTING",
    }

    for line in lines[1:]:
        parts = line.split(maxsplit=7)

        if len(parts) < 7:
            continue

        count += 1

        sock_type = type_names.get(parts[4], parts[4])
        state = state_names.get(parts[5], parts[5])

        types[sock_type] += 1
        states[state] += 1

        try:
            inode = int(parts[6])
            inodes.add(inode)
        except ValueError:
            pass

        if len(parts) > 7:
            paths[parts[7]] += 1

    return {
        "count": count,
        "types": dict(sorted(types.items())),
        "states": dict(sorted(states.items())),
        "named_paths": sum(paths.values()),
        "inodes": inodes,
    }


def count_table(lines: list[str]) -> int:
    if not lines:
        return 0

    return sum(1 for line in lines[1:] if line.strip())


def get_process_name(root: Path, pid: int) -> str:
    path = root / str(pid) / "comm"

    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace",
        ).strip()
    except OSError:
        return "unknown"


def discover_owners(
    root: Path,
    target_inodes: set[int],
    limit: int,
) -> dict[str, Any]:
    owners = defaultdict(set)
    scanned = 0
    inaccessible = 0

    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise SocketStatsError(
            f"Cannot enumerate processes: {exc}"
        ) from exc

    for entry in entries:
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)
        fd_path = entry / "fd"

        try:
            descriptors = list(fd_path.iterdir())
        except OSError:
            inaccessible += 1
            continue

        scanned += 1

        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue

            if not target.startswith("socket:["):
                continue

            try:
                inode = int(target[8:-1])
            except ValueError:
                continue

            if inode in target_inodes:
                owners[inode].add(pid)

    process_counts = Counter()
    process_names = {}

    for pids in owners.values():
        for pid in pids:
            process_counts[pid] += 1

            if pid not in process_names:
                process_names[pid] = get_process_name(root, pid)

    processes = []

    for pid, count in process_counts.most_common(limit):
        processes.append({
            "pid": pid,
            "name": process_names[pid],
            "sockets": count,
        })

    return {
        "scanned_processes": scanned,
        "inaccessible_processes": inaccessible,
        "matched_inodes": len(owners),
        "processes": processes,
        "note": (
            "Socket ownership may be incomplete without "
            "permission to inspect other processes."
        ),
    }


def flatten_numeric(
    data: Any,
    prefix: str = "",
) -> dict[str, int | float]:
    result = {}

    if not isinstance(data, dict):
        return result

    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            result.update(flatten_numeric(value, path))

        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            result[path] = value

    return result


def calculate_changes(
    current: dict[str, Any],
    previous: dict[str, Any],
    elapsed: float,
) -> dict[str, Any]:
    current_gauges = flatten_numeric(current.get("summary", {}))
    previous_gauges = flatten_numeric(previous.get("summary", {}))

    current_counters = flatten_numeric(current.get("counters", {}))
    previous_counters = flatten_numeric(previous.get("counters", {}))

    changes = {}
    rates = {}

    for key, value in current_gauges.items():
        if key in previous_gauges:
            difference = value - previous_gauges[key]

            if difference:
                changes[key] = difference

    for key, value in current_counters.items():
        if key not in previous_counters:
            continue

        difference = value - previous_counters[key]

        if difference < 0:
            continue

        if difference:
            changes[key] = difference

        if elapsed > 0:
            rates[key] = round(difference / elapsed, 3)

    return {
        "elapsed_seconds": round(elapsed, 3),
        "changes": changes,
        "counter_rates_per_second": rates,
    }


class SocketCollector:
    def __init__(self, config: Config):
        self.config = config

    def collect(self) -> dict[str, Any]:
        reader = ProcReader(
            self.config.proc_root,
            self.config.max_file_bytes,
            self.config.verbose,
        )

        started = time.perf_counter()

        sockstat4 = parse_sockstat(
            reader.read("net/sockstat", optional=False)
        )

        sockstat6 = parse_sockstat(
            reader.read("net/sockstat6")
        )

        summary = {
            "sockets_used": sockstat4.get("sockets", {}).get("used", 0),
            "tcp": sockstat4.get("tcp", {}),
            "udp": sockstat4.get("udp", {}),
            "udplite": sockstat4.get("udplite", {}),
            "raw": sockstat4.get("raw", {}),
            "frag": sockstat4.get("frag", {}),
        }

        if self.config.extended:
            summary["ipv6"] = sockstat6

        tables = {}
        all_inodes = set()
        tcp_states = Counter()

        for name, (path, protocol, family) in SOCKET_TABLES.items():
            if family == 6 and not self.config.extended:
                continue

            lines = reader.read(path)

            table = parse_inet_table(
                lines,
                protocol,
                family,
            )

            all_inodes.update(table["inodes"])
            tcp_states.update(table["states"])

            tables[name] = {
                "count": table["count"],
                "states": table["states"],
            }

        unix_data = parse_unix(
            reader.read("net/unix")
        )

        all_inodes.update(unix_data["inodes"])

        summary["unix"] = {
            "count": unix_data["count"],
            "types": unix_data["types"],
            "states": unix_data["states"],
            "named_paths": unix_data["named_paths"],
        }

        summary["netlink"] = {
            "count": count_table(reader.read("net/netlink"))
        }

        summary["packet"] = {
            "count": count_table(reader.read("net/packet"))
        }

        summary["tcp_states"] = dict(sorted(tcp_states.items()))

        summary["table_counts"] = {
            name: table["count"]
            for name, table in tables.items()
        }

        snmp = parse_mib(
            reader.read("net/snmp")
        )

        netstat = parse_mib(
            reader.read("net/netstat")
        )

        snmp6 = {}

        if self.config.extended:
            for line in reader.read("net/snmp6"):
                parts = line.split()

                if len(parts) != 2:
                    continue

                try:
                    snmp6[parts[0]] = int(parts[1])
                except ValueError:
                    continue

        counters = {}

        for source in (snmp, netstat):
            for section, fields in source.items():
                counters.setdefault(section, {}).update(fields)

        if snmp6:
            counters["IPv6"] = snmp6

        result = {
            "metadata": {
                "version": VERSION,
                "hostname": socket.gethostname(),
                "timestamp": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "proc_root": str(self.config.proc_root),
                "pid": os.getpid(),
            },
            "summary": summary,
            "tables": tables,
            "counters": counters,
            "warnings": reader.warnings,
        }

        if self.config.processes:
            try:
                result["ownership"] = discover_owners(
                    self.config.proc_root,
                    all_inodes,
                    self.config.process_limit,
                )
            except SocketStatsError as exc:
                result["warnings"].append(str(exc))

        self.evaluate_thresholds(result)

        if self.config.performance:
            usage = resource.getrusage(resource.RUSAGE_SELF)

            result["performance"] = {
                "collection_seconds": round(
                    time.perf_counter() - started, 6
                ),
                "peak_memory_mb": round(
                    usage.ru_maxrss / 1024, 2
                ),
                "user_cpu_seconds": round(usage.ru_utime, 4),
                "system_cpu_seconds": round(usage.ru_stime, 4),
            }

        return result

    def evaluate_thresholds(self, result: dict[str, Any]) -> None:
        summary = result["summary"]
        warnings = result["warnings"]

        tcp = summary.get("tcp", {})
        states = summary.get("tcp_states", {})

        checks = [
            (
                "TCP allocated",
                tcp.get("alloc", 0),
                self.config.threshold_tcp,
            ),
            (
                "TCP established",
                states.get("ESTABLISHED", 0),
                self.config.threshold_established,
            ),
            (
                "TCP time-wait",
                states.get("TIME_WAIT", 0),
                self.config.threshold_timewait,
            ),
            (
                "TCP orphan",
                tcp.get("orphan", 0),
                self.config.threshold_orphan,
            ),
        ]

        for label, value, threshold in checks:
            if threshold is not None and value >= threshold:
                warnings.append(
                    f"{label} threshold reached: "
                    f"{value} >= {threshold}"
                )

        threshold = self.config.threshold_retrans

        if threshold is not None:
            tcp_counters = result["counters"].get("Tcp", {})
            outgoing = tcp_counters.get("OutSegs", 0)
            retrans = tcp_counters.get("RetransSegs", 0)

            if outgoing > 0:
                ratio = retrans / outgoing * 100

                if ratio >= threshold:
                    warnings.append(
                        "Cumulative TCP retransmission ratio "
                        f"{ratio:.2f}% >= {threshold:.2f}%"
                    )


def format_number(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:,.3f}"

    if isinstance(value, int):
        return f"{value:,}"

    return str(value)


def format_table(
    rows: list[tuple[str, Any]],
    width: int = 28,
) -> list[str]:
    return [
        f"  {label:<{width}} {format_number(value)}"
        for label, value in rows
    ]


def format_human(data: dict[str, Any], config: Config) -> str:
    metadata = data["metadata"]
    summary = data["summary"]
    lines = []

    lines.append("SOCKET STATISTICS")
    lines.append("=" * 72)
    lines.append(f"Host:       {metadata['hostname']}")
    lines.append(f"Timestamp:  {metadata['timestamp']}")
    lines.append(f"Source:     {metadata['proc_root']}")
    lines.append(f"Version:    {metadata['version']}")
    lines.append("")

    lines.append("SOCKET SUMMARY")
    lines.append("-" * 72)

    rows = [
        ("Sockets used", summary.get("sockets_used", 0)),
        ("TCP allocated", summary.get("tcp", {}).get("alloc", 0)),
        ("TCP in use", summary.get("tcp", {}).get("inuse", 0)),
        ("TCP orphan", summary.get("tcp", {}).get("orphan", 0)),
        ("TCP time-wait", summary.get("tcp", {}).get("tw", 0)),
        ("UDP in use", summary.get("udp", {}).get("inuse", 0)),
        ("RAW in use", summary.get("raw", {}).get("inuse", 0)),
        ("UNIX sockets", summary.get("unix", {}).get("count", 0)),
        ("Netlink sockets", summary.get("netlink", {}).get("count", 0)),
        ("Packet sockets", summary.get("packet", {}).get("count", 0)),
    ]

    lines.extend(format_table(rows))
    lines.append("")

    lines.append("SOCKET MEMORY")
    lines.append("-" * 72)

    memory_rows = []

    for protocol in ("tcp", "udp", "frag"):
        fields = summary.get(protocol, {})

        for field in MEMORY_FIELDS:
            if field in fields:
                memory_rows.append((
                    f"{protocol.upper()} {field} (pages)",
                    fields[field],
                ))

    if memory_rows:
        lines.extend(format_table(memory_rows))
    else:
        lines.append("  No memory counters available")

    lines.append("")
    lines.append("TCP CONNECTION STATES")
    lines.append("-" * 72)

    states = summary.get("tcp_states", {})

    if states:
        lines.extend(
            format_table(
                sorted(
                    states.items(),
                    key=lambda item: (-item[1], item[0]),
                )
            )
        )
    else:
        lines.append("  No TCP entries found")

    lines.append("")
    lines.append("PROTOCOL TABLES")
    lines.append("-" * 72)

    lines.extend(
        format_table(
            sorted(summary.get("table_counts", {}).items())
        )
    )

    if config.extended:
        lines.append("")
        lines.append("IPV6 SOCKET STATISTICS")
        lines.append("-" * 72)

        ipv6_rows = []

        for protocol, fields in summary.get("ipv6", {}).items():
            for key, value in fields.items():
                ipv6_rows.append(
                    (f"{protocol.upper()} {key}", value)
                )

        if ipv6_rows:
            lines.extend(format_table(ipv6_rows))
        else:
            lines.append("  No IPv6 statistics available")

        lines.append("")
        lines.append("UNIX SOCKET TYPES")
        lines.append("-" * 72)

        lines.extend(
            format_table(
                sorted(summary["unix"]["types"].items())
            )
        )

        lines.append("")
        lines.append("KERNEL NETWORK COUNTERS")
        lines.append("-" * 72)

        for section, keys in IMPORTANT_COUNTERS.items():
            counters = data["counters"].get(section, {})

            selected = [
                (f"{section}.{key}", counters[key])
                for key in keys
                if key in counters
            ]

            if selected:
                lines.extend(format_table(selected))

    if "ownership" in data:
        ownership = data["ownership"]

        lines.append("")
        lines.append("SOCKET OWNERSHIP")
        lines.append("-" * 72)

        lines.extend(format_table([
            ("Processes scanned", ownership["scanned_processes"]),
            ("Processes inaccessible", ownership["inaccessible_processes"]),
            ("Matched socket inodes", ownership["matched_inodes"]),
        ]))

        lines.append("")
        lines.append(
            f"  {'PID':>8}  {'SOCKETS':>10}  PROCESS"
        )

        for process in ownership["processes"]:
            lines.append(
                f"  {process['pid']:>8}  "
                f"{process['sockets']:>10}  "
                f"{process['name']}"
            )

    if "sampling" in data:
        sampling = data["sampling"]

        lines.append("")
        lines.append("CHANGES SINCE PREVIOUS SAMPLE")
        lines.append("-" * 72)

        lines.append(
            f"  Interval: {sampling['elapsed_seconds']:.3f} seconds"
        )

        changes = sampling.get("changes", {})

        for key, value in sorted(changes.items()):
            lines.append(f"  {key:<42} {value:+,}")

        rates = sampling.get("counter_rates_per_second", {})

        if rates:
            lines.append("")
            lines.append("COUNTER RATES PER SECOND")
            lines.append("-" * 72)

            for key, value in sorted(rates.items()):
                if value:
                    lines.append(f"  {key:<42} {value:,.3f}/s")

    if "performance" in data:
        lines.append("")
        lines.append("PERFORMANCE")
        lines.append("-" * 72)

        lines.extend(
            format_table(
                list(data["performance"].items())
            )
        )

    if data.get("warnings"):
        lines.append("")
        lines.append("WARNINGS")
        lines.append("-" * 72)

        for warning in data["warnings"]:
            lines.append(f"  {warning}")

    lines.append("")

    return "\n".join(lines)


def flatten_csv(data: dict[str, Any]) -> str:
    flattened = {}

    for section in ("summary", "counters", "performance"):
        flattened.update(
            flatten_numeric(data.get(section, {}), section)
        )

    flattened["timestamp"] = data["metadata"]["timestamp"]
    flattened["hostname"] = data["metadata"]["hostname"]

    if "sampling" in data:
        flattened.update(
            flatten_numeric(data["sampling"], "sampling")
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(flattened.keys())
    writer.writerow(flattened.values())

    return buffer.getvalue().rstrip("\n")


class OutputManager:
    def __init__(self, config: Config):
        self.config = config
        self.first_sample = True

        if config.output_file:
            self.stream = open(
                config.output_file,
                "w",
                encoding="utf-8",
                newline="",
            )
            self.owns_stream = True
        else:
            self.stream = sys.stdout
            self.owns_stream = False

    def emit(self, data: dict[str, Any]) -> None:
        if self.config.quiet:
            return

        if self.config.output_format == "json":
            content = json.dumps(
                data,
                indent=None if self.config.watch else 2,
                ensure_ascii=False,
                sort_keys=True,
            )

        elif self.config.output_format == "csv":
            content = flatten_csv(data)

            if not self.first_sample:
                content = "\n".join(content.splitlines()[1:])

        else:
            content = format_human(data, self.config)

            if not self.first_sample:
                content = "\n" + content

        self.stream.write(content + "\n")
        self.stream.flush()

        self.first_sample = False

    def close(self) -> None:
        if self.owns_stream:
            self.stream.close()


class Application:
    def __init__(self, config: Config):
        self.config = config
        self.collector = SocketCollector(config)
        self.running = True

    def stop(self, signum, frame) -> None:
        self.running = False

    def run(self) -> int:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        output = OutputManager(self.config)

        previous = None
        previous_time = None
        completed = 0

        try:
            while self.running:
                started = time.monotonic()
                data = self.collector.collect()

                if previous is not None and previous_time is not None:
                    elapsed = started - previous_time

                    data["sampling"] = calculate_changes(
                        data,
                        previous,
                        elapsed,
                    )

                output.emit(data)

                previous = data
                previous_time = started
                completed += 1

                if not self.config.watch:
                    break

                if self.config.count and completed >= self.config.count:
                    break

                remaining = self.config.interval - (
                    time.monotonic() - started
                )

                deadline = time.monotonic() + max(remaining, 0)

                while self.running:
                    wait = deadline - time.monotonic()

                    if wait <= 0:
                        break

                    time.sleep(min(wait, 0.2))

        finally:
            output.close()

        return 0


def nonnegative_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Expected an integer"
        ) from exc

    if result < 0:
        raise argparse.ArgumentTypeError(
            "Value cannot be negative"
        )

    return result


def positive_float(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Expected a number"
        ) from exc

    if not 0 < result < float("inf"):
        raise argparse.ArgumentTypeError(
            "Value must be finite and greater than zero"
        )

    return result


def parse_arguments() -> Config:
    parser = argparse.ArgumentParser(
        prog="sockets_stat.py",
        description=(
            "Linux socket statistics and network diagnostics "
            "using the proc filesystem."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"Socket Statistics Tool {VERSION}",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON",
    )

    parser.add_argument(
        "--csv",
        action="store_true",
        help="Output CSV",
    )

    parser.add_argument(
        "--extended",
        action="store_true",
        help="Include IPv6 and extended network counters",
    )

    parser.add_argument(
        "--processes",
        action="store_true",
        help="Discover socket ownership by process",
    )

    parser.add_argument(
        "--process-limit",
        type=nonnegative_int,
        default=20,
        help="Maximum number of processes to display",
    )

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Collect socket statistics repeatedly",
    )

    parser.add_argument(
        "--interval",
        type=positive_float,
        default=2.0,
        help="Seconds between samples",
    )

    parser.add_argument(
        "--count",
        type=nonnegative_int,
        default=0,
        help="Number of samples in watch mode; zero means unlimited",
    )

    parser.add_argument(
        "--proc-root",
        default="/proc",
        help="Root of the proc filesystem",
    )

    parser.add_argument(
        "--path",
        default=None,
        help="Alternative sockstat file path",
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Write output to a file",
    )

    parser.add_argument(
        "--performance",
        action="store_true",
        help="Include performance metrics",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress normal output",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Report missing optional proc files",
    )

    parser.add_argument(
        "--threshold-tcp",
        type=nonnegative_int,
        default=None,
    )

    parser.add_argument(
        "--threshold-established",
        type=nonnegative_int,
        default=None,
    )

    parser.add_argument(
        "--threshold-timewait",
        type=nonnegative_int,
        default=None,
    )

    parser.add_argument(
        "--threshold-orphan",
        type=nonnegative_int,
        default=None,
    )

    parser.add_argument(
        "--threshold-retrans",
        type=float,
        default=None,
        help="Cumulative retransmission percentage threshold",
    )

    parser.add_argument(
        "--max-file-bytes",
        type=nonnegative_int,
        default=32 * 1024 * 1024,
        help="Maximum bytes to read from each proc file",
    )

    args = parser.parse_args()

    if args.json and args.csv:
        parser.error("--json and --csv cannot be combined")

    if args.threshold_retrans is not None:
        if not 0 <= args.threshold_retrans <= 100:
            parser.error(
                "--threshold-retrans must be between 0 and 100"
            )

    if args.max_file_bytes == 0:
        parser.error("--max-file-bytes must be greater than zero")

    root = Path(args.proc_root).expanduser().resolve()

    if args.path:
        sockstat = Path(args.path).expanduser().resolve()

        if sockstat.name != "sockstat":
            parser.error("--path must point to a sockstat file")

        if sockstat.parent.name != "net":
            parser.error("--path must point to a net/sockstat file")

        root = sockstat.parent.parent

    if not root.is_dir():
        parser.error(f"Proc root is not a directory: {root}")

    output_format = "human"

    if args.json:
        output_format = "json"
    elif args.csv:
        output_format = "csv"

    return Config(
        proc_root=root,
        output_format=output_format,
        output_file=args.output,
        extended=args.extended,
        processes=args.processes,
        process_limit=args.process_limit,
        watch=args.watch,
        interval=args.interval,
        count=args.count,
        performance=args.performance,
        quiet=args.quiet,
        verbose=args.verbose,
        threshold_tcp=args.threshold_tcp,
        threshold_established=args.threshold_established,
        threshold_timewait=args.threshold_timewait,
        threshold_orphan=args.threshold_orphan,
        threshold_retrans=args.threshold_retrans,
        max_file_bytes=args.max_file_bytes,
    )


def main() -> int:
    try:
        config = parse_arguments()
        application = Application(config)
        return application.run()

    except BrokenPipeError:
        return 0

    except (SocketStatsError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
