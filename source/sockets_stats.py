#!/usr/bin/env python3

import os
import sys
import json
import time
import argparse
import datetime
import resource
from pathlib import Path
from enum import Enum
from typing import Dict, List, Any, Optional, Union, Callable
from dataclasses import dataclass

class LogLevel(Enum):
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3

@dataclass
class ToolConfig:
    log_level: LogLevel = LogLevel.INFO
    json_output: bool = False
    show_performance: bool = False
    quiet: bool = False
    extended: bool = False
    sockstat_path: str = '/proc/net/sockstat'
    output_file: Optional[str] = None

class SocketStatsTool:
    def __init__(self) -> None:
        self.config = ToolConfig()
        self.start_time = time.time()
        self.max_file_size = 10 * 1024 * 1024
        self.max_line_length = 1024 * 1024
        self.allowed_proc_dirs = [
            Path('/proc/net').resolve(),
            Path('/proc').resolve(),
            Path('/tmp/socket-stats').resolve() if Path('/tmp/socket-stats').exists() else None
        ]
        self.allowed_proc_dirs = [d for d in self.allowed_proc_dirs if d is not None]

        self.protocol_parsers: Dict[str, Callable] = {
            'sockets:': self.parse_sockets_section,
            'TCP:': lambda p, s: self.parse_protocol_section(p, s, 'tcp', {
                'inuse': 'in_use', 'orphan': 'orphan', 'tw': 'time_wait', 
                'alloc': 'allocated', 'mem': 'memory'
            }),
            'UDP:': lambda p, s: self.parse_protocol_section(p, s, 'udp', {
                'inuse': 'in_use', 'mem': 'memory'
            }),
            'UDPLITE:': lambda p, s: self.parse_protocol_section(p, s, 'udp_lite', {
                'inuse': 'in_use'
            }),
            'RAW:': lambda p, s: self.parse_protocol_section(p, s, 'raw', {
                'inuse': 'in_use'
            }),
            'FRAG:': lambda p, s: self.parse_protocol_section(p, s, 'frag', {
                'inuse': 'in_use', 'memory': 'memory'
            }),
            'TCP6:': lambda p, s: self.parse_protocol_section(p, s, 'tcp6', {
                'inuse': 'in_use', 'orphan': 'orphan', 'tw': 'time_wait', 
                'alloc': 'allocated', 'mem': 'memory'
            }) if self.config.extended else None,
            'UDP6:': lambda p, s: self.parse_protocol_section(p, s, 'udp6', {
                'inuse': 'in_use', 'mem': 'memory'
            }) if self.config.extended else None
        }
        
        self.protocol_parsers = {k: v for k, v in self.protocol_parsers.items() if v is not None}

    def run(self) -> None:
        exit_code = 0
        try:
            self.parse_command_line()
            
            if self.config.quiet and (self.config.json_output or self.config.show_performance):
                self.log_message(LogLevel.WARNING, "--quiet flag is active, but output will still be generated for JSON and performance modes")

            self.validate_config()
            self.check_sockstat_file()
            
            stats = self.get_socket_stats()
            
            if not self.config.quiet:
                self.display_stats(stats)

            if self.config.show_performance:
                self.show_performance_metrics()
            
        except SystemExit:
            raise
        except Exception as e:
            self.log_message(LogLevel.ERROR, str(e))
            exit_code = 1
        
        sys.exit(exit_code)

    def parse_command_line(self) -> None:
        parser = argparse.ArgumentParser(description='Socket Statistics Tool', add_help=False)
        parser.add_argument('--json', action='store_true', help='Output socket summary in JSON format')
        parser.add_argument('--log-level', type=str, help='Set log level (DEBUG, INFO, WARNING, ERROR)')
        parser.add_argument('--help', action='store_true', help='Display help message')
        parser.add_argument('--path', type=str, help='Path to sockstat file (default: /proc/net/sockstat)')
        parser.add_argument('--performance', action='store_true', help='Show performance metrics')
        parser.add_argument('--quiet', action='store_true', help='Suppress all non-error output')
        parser.add_argument('--extended', action='store_true', help='Show extended protocol information')
        parser.add_argument('--version', action='store_true', help='Display version information')
        parser.add_argument('--output', type=str, help='Write output to specified file')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose output (same as --log-level DEBUG)')
        
        args = parser.parse_args()
        
        if args.json:
            self.config.json_output = True
        
        if args.verbose:
            self.config.log_level = LogLevel.DEBUG
        elif args.log_level:
            try:
                self.config.log_level = LogLevel[args.log_level.upper()]
            except KeyError:
                valid_levels = ', '.join([level.name for level in LogLevel])
                raise RuntimeError(f"Invalid log level: {args.log_level}. Valid levels: {valid_levels}")
        
        if args.help:
            self.show_help()
            sys.exit(0)
        
        if args.path:
            self.config.sockstat_path = self.sanitize_path(args.path)
        
        if args.performance:
            self.config.show_performance = True
        
        if args.quiet:
            self.config.quiet = True
        
        if args.extended:
            self.config.extended = True
        
        if args.output:
            self.config.output_file = self.sanitize_path(args.output)
        
        if args.version:
            if not args.quiet:
                self.show_version()
            sys.exit(0)

    def sanitize_path(self, path: str) -> str:
        path = path.replace('\0', '')
        path = os.path.normpath(path)
        
        if '..' in path.split(os.sep):
            raise RuntimeError("Path traversal detected in path")
        
        return path

    def is_path_allowed(self, path: Path) -> bool:
        try:
            resolved_path = path.resolve()
        except (RuntimeError, OSError):
            return False
        
        for allowed_dir in self.allowed_proc_dirs:
            if allowed_dir in resolved_path.parents or resolved_path == allowed_dir:
                return True
        
        return False

    def validate_config(self) -> None:
        if not isinstance(self.config.log_level, LogLevel):
            raise RuntimeError(f"Invalid log level configuration")
        
        if '\0' in self.config.sockstat_path or '..' in self.config.sockstat_path.split(os.sep):
            raise RuntimeError("Invalid path: potential path traversal attack detected")
        
        if self.config.output_file:
            if '\0' in self.config.output_file or '..' in self.config.output_file.split(os.sep):
                raise RuntimeError("Invalid output file path: potential path traversal attack detected")
            
            output_dir = Path(self.config.output_file).parent
            if not output_dir.exists():
                raise RuntimeError(f"Output directory does not exist: {output_dir}")
            
            if not os.access(str(output_dir), os.W_OK):
                raise RuntimeError(f"Output directory is not writable: {output_dir}")

    def check_sockstat_file(self) -> None:
        path = Path(self.config.sockstat_path)
        
        if path.is_symlink():
            real_path = path.resolve()
            if not real_path.exists():
                raise RuntimeError(f"Cannot resolve symbolic link: {self.config.sockstat_path}")
            
            if not self.is_path_allowed(real_path):
                raise RuntimeError(f"Symbolic link target not allowed: {real_path}")
            
            self.config.sockstat_path = str(real_path)
            path = real_path
        
        if not self.is_path_allowed(path):
            raise RuntimeError(f"Path not allowed: {self.config.sockstat_path}")
        
        if not path.exists():
            raise RuntimeError(
                f"'{self.config.sockstat_path}' not found. "
                "Ensure you are running on a Linux system or specify --path for an alternate file"
            )
        
        if not os.access(str(path), os.R_OK):
            raise RuntimeError(f"Cannot read '{self.config.sockstat_path}'")
        
        if path.is_dir():
            raise RuntimeError(f"'{self.config.sockstat_path}' is a directory, expected a file")
        
        try:
            file_size = path.stat().st_size
            if file_size > self.max_file_size:
                self.log_message(LogLevel.WARNING, f"File size {file_size} exceeds threshold {self.max_file_size}")
        except OSError as e:
            raise RuntimeError(f"Cannot access file stats: {str(e)}")

    def safe_open_file(self, file_path: str, mode: str = 'r'):
        path = Path(file_path)
        
        if not self.is_path_allowed(path):
            raise RuntimeError(f"Path not allowed: {file_path}")
        
        if not path.exists():
            return None
        
        if not os.access(str(path), os.R_OK):
            return None
        
        try:
            file_size = path.stat().st_size
            if file_size > self.max_file_size:
                self.log_message(LogLevel.WARNING, f"File size {file_size} exceeds threshold {self.max_file_size}")
                return None
        except OSError:
            return None
        
        return open(str(path), mode)

    def log_message(self, level: LogLevel, message: str) -> None:
        if level.value < self.config.log_level.value:
            return
        
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted_message = f'[{timestamp}] {level.name}: {message}'
        
        if level == LogLevel.ERROR:
            print(formatted_message, file=sys.stderr)
        elif not self.config.json_output:
            print(formatted_message)

    def show_version(self) -> None:
        print("Socket Statistics Tool 1.2.0")
        print(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

    def show_help(self) -> None:
        help_text = """Socket Statistics Tool 1.2.0

Usage: socket_stats.py [OPTIONS]

Options:
  --json                 Output socket summary in JSON format
  --log-level LEVEL      Set log level (DEBUG, INFO, WARNING, ERROR)
  --verbose              Enable verbose output (same as --log-level DEBUG)
  --path PATH            Path to sockstat file (default: /proc/net/sockstat)
  --performance          Show performance metrics
  --quiet                Suppress all non-error output
  --extended             Show extended protocol information
  --output FILE          Write output to specified file
  --version              Display version information
  --help                 Display this help message

Examples:
  socket_stats.py --json
  socket_stats.py --log-level DEBUG
  socket_stats.py --json --log-level WARNING
  socket_stats.py --path /tmp/test-sockstat --json
  socket_stats.py --performance --json
  socket_stats.py --quiet --json
  socket_stats.py --extended --json --output results.json

Note: The --quiet flag suppresses regular output but not JSON output or error messages.

"""
        print(help_text)

    def read_file_lines(self, file_path: str) -> List[str]:
        lines = []
        file_obj = self.safe_open_file(file_path)
        if not file_obj:
            return lines
        
        try:
            with file_obj as f:
                for line in f:
                    if len(line) > self.max_line_length:
                        self.log_message(LogLevel.WARNING, f"Line exceeds maximum length in {file_path}, skipping")
                        continue
                    lines.append(line.rstrip('\n'))
        except Exception as e:
            self.log_message(LogLevel.DEBUG, f"Error reading {file_path}: {str(e)}")
        
        return lines

    def get_socket_stats(self) -> Dict[str, Any]:
        self.log_message(LogLevel.INFO, f"Reading socket statistics from {self.config.sockstat_path}")
        
        stats = {
            'metadata': {
                'source': self.config.sockstat_path,
                'generated_at': datetime.datetime.now().isoformat(),
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown'
            },
            'sockets_used': 0,
            'tcp': {
                'in_use': 0,
                'orphan': 0,
                'time_wait': 0,
                'allocated': 0,
                'memory': 0
            },
            'udp': {
                'in_use': 0,
                'memory': 0
            },
            'udp_lite': {
                'in_use': 0
            },
            'raw': {
                'in_use': 0
            },
            'frag': {
                'in_use': 0,
                'memory': 0
            }
        }

        if self.config.extended:
            self.initialize_extended_stats(stats)
            stats['tcp6'] = {
                'in_use': 0,
                'orphan': 0,
                'time_wait': 0,
                'allocated': 0,
                'memory': 0
            }
            stats['udp6'] = {
                'in_use': 0,
                'memory': 0
            }
        
        try:
            lines = self.read_file_lines(self.config.sockstat_path)
            line_count = 0
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                self.parse_sockstat_line(line, stats)
                line_count += 1
            
            self.log_message(LogLevel.DEBUG, f"Processed {line_count} lines from sockstat file")
            
        except Exception as e:
            raise RuntimeError(f"Failed to read {self.config.sockstat_path}: {str(e)}") from e

        if self.config.extended:
            self.load_extended_protocol_info(stats)
        
        return stats

    def initialize_extended_stats(self, stats: Dict[str, Any]) -> None:
        stats['unix'] = {
            'in_use': 0,
            'dynamic': 0,
            'inode': 0
        }
        
        stats['icmp'] = {
            'in_use': 0
        }
        
        stats['icmp6'] = {
            'in_use': 0
        }
        
        stats['netlink'] = {
            'in_use': 0
        }
        
        stats['packet'] = {
            'in_use': 0,
            'memory': 0
        }

    def parse_sockstat_line(self, line: str, stats: Dict[str, Any]) -> None:
        parts = line.split()
        if len(parts) < 2:
            self.log_message(LogLevel.DEBUG, f"Skipping malformed line: {line}")
            return
        
        section = parts[0]
        
        if section in self.protocol_parsers:
            self.protocol_parsers[section](parts, stats)
        else:
            self.log_message(LogLevel.DEBUG, f"Unknown section: {section}")

    def parse_sockets_section(self, parts: List[str], stats: Dict[str, Any]) -> None:
        if len(parts) >= 3:
            parsed_value = self.parse_int(parts[2])
            if parsed_value is not None:
                stats['sockets_used'] = parsed_value

    def load_extended_protocol_info(self, stats: Dict[str, Any]) -> None:
        proc_files = [
            ('unix', '/proc/net/unix', self.parse_unix_sockets),
            ('netlink', '/proc/net/netlink', self.parse_count_file),
            ('packet', '/proc/net/packet', self.parse_count_file),
            ('icmp', '/proc/net/snmp', self.parse_icmp_snmp),
            ('icmp6', '/proc/net/snmp', self.parse_icmp6_snmp)
        ]
        
        for protocol, file_path, parser in proc_files:
            if protocol in stats:
                parser(file_path, stats, protocol)
        
        self.load_additional_network_stats(stats)

    def parse_unix_sockets(self, file_path: str, stats: Dict[str, Any], protocol: str) -> None:
        lines = self.read_file_lines(file_path)
        if not lines:
            return
        
        unix_count = 0
        for i, line in enumerate(lines):
            if i == 0:
                continue
            if line.strip():
                unix_count += 1
        
        stats['unix']['in_use'] = unix_count

    def parse_count_file(self, file_path: str, stats: Dict[str, Any], protocol: str) -> None:
        lines = self.read_file_lines(file_path)
        if not lines:
            return
        
        count = 0
        for i, line in enumerate(lines):
            if i == 0:
                continue
            if line.strip():
                count += 1
        
        stats[protocol]['in_use'] = count

    def parse_icmp_snmp(self, file_path: str, stats: Dict[str, Any], protocol: str) -> None:
        lines = self.read_file_lines(file_path)
        if not lines:
            return
        
        in_icmp_line = False
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('Icmp:'):
                in_icmp_line = True
                continue
            
            if in_icmp_line:
                parts = line.split()
                if parts:
                    parsed_value = self.parse_int(parts[0])
                    if parsed_value is not None:
                        stats['icmp']['in_use'] = parsed_value
                break

    def parse_icmp6_snmp(self, file_path: str, stats: Dict[str, Any], protocol: str) -> None:
        lines = self.read_file_lines(file_path)
        if not lines:
            return
        
        in_icmp6_line = False
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('Icmp6:'):
                in_icmp6_line = True
                continue
            
            if in_icmp6_line:
                parts = line.split()
                if parts:
                    parsed_value = self.parse_int(parts[0])
                    if parsed_value is not None:
                        stats['icmp6']['in_use'] = parsed_value
                break

    def load_additional_network_stats(self, stats: Dict[str, Any]) -> None:
        lines = self.read_file_lines('/proc/net/netstat')
        
        for line in lines:
            line = line.strip()
            if line.startswith('TcpExt:'):
                self.parse_tcp_extended_stats(line, stats)

    def parse_tcp_extended_stats(self, line: str, stats: Dict[str, Any]) -> None:
        parts = line.split()
        if len(parts) < 2:
            return
        
        if 'tcp_ext' not in stats:
            stats['tcp_ext'] = {}
        
        for i in range(1, len(parts), 2):
            if i + 1 >= len(parts):
                break
            
            key = parts[i]
            value = parts[i + 1]
            
            parsed_value = self.parse_int(value)
            if parsed_value is not None:
                stats['tcp_ext'][key] = parsed_value

    def parse_protocol_section(self, parts: List[str], stats: Dict[str, Any], 
                              protocol: str, mapping: Dict[str, str]) -> None:
        if protocol not in stats:
            stats[protocol] = {}
        
        for i in range(1, len(parts), 2):
            if i + 1 >= len(parts):
                break
            
            key = parts[i]
            value = parts[i + 1]
            
            if key in mapping:
                parsed_value = self.parse_int(value)
                if parsed_value is not None:
                    stats[protocol][mapping[key]] = parsed_value
            else:
                self.log_message(LogLevel.DEBUG, f"Unknown {protocol} field: {key}")

    def parse_int(self, value: str) -> Optional[int]:
        try:
            return int(value)
        except ValueError:
            self.log_message(LogLevel.WARNING, f"Failed to parse integer: '{value}'")
            return None

    def display_stats(self, stats: Dict[str, Any]) -> None:
        output = self.generate_output(stats)
        
        if self.config.output_file:
            try:
                with open(self.config.output_file, 'w') as f:
                    f.write(output)
                self.log_message(LogLevel.INFO, f"Output written to {self.config.output_file}")
            except Exception as e:
                raise RuntimeError(f"Failed to write output to {self.config.output_file}: {str(e)}")
        elif not self.config.quiet:
            print(output)

    def generate_output(self, stats: Dict[str, Any]) -> str:
        if self.config.json_output:
            return self.generate_json_output(stats)
        else:
            return self.generate_human_readable_output(stats)

    def generate_json_output(self, stats: Dict[str, Any]) -> str:
        try:
            return json.dumps(stats, indent=2, ensure_ascii=False)
        except Exception as e:
            raise RuntimeError(f'Failed to encode JSON: {str(e)}')

    def generate_human_readable_output(self, stats: Dict[str, Any]) -> str:
        lines = []
        lines.append("Socket Statistics")
        lines.append("=================")
        lines.append(f"Generated: {stats['metadata']['generated_at']}")
        lines.append(f"Hostname:  {stats['metadata']['hostname']}")
        lines.append(f"Source:    {stats['metadata']['source']}")
        lines.append("")
        
        lines.append(f"Sockets used: {stats['sockets_used']}")
        lines.append("")
        
        protocols = [
            ('tcp', 'TCP'),
            ('udp', 'UDP'),
            ('udp_lite', 'UDPLite'),
            ('raw', 'RAW'),
            ('frag', 'FRAG')
        ]
        
        if self.config.extended:
            protocols.extend([
                ('tcp6', 'TCP6'),
                ('udp6', 'UDP6')
            ])
        
        for protocol_key, protocol_name in protocols:
            if protocol_key in stats and stats[protocol_key]:
                has_values = any(v != 0 for v in stats[protocol_key].values())
                if has_values:
                    lines.append(f"{protocol_name}:")
                    for key, value in stats[protocol_key].items():
                        if value is not None:
                            display_key = key.replace('_', ' ').title()
                            suffix = ' pages' if key == 'memory' else ''
                            lines.append(f"  {display_key:<12} {value}{suffix}")
                    lines.append("")

        if self.config.extended:
            lines.extend(self.generate_extended_human_readable_output(stats))
        
        return '\n'.join(lines)

    def generate_extended_human_readable_output(self, stats: Dict[str, Any]) -> List[str]:
        lines = []
        lines.append("Extended Protocol Information:")
        lines.append("=============================")
        
        extended_protocols = [
            ('unix', 'UNIX'),
            ('netlink', 'Netlink'),
            ('packet', 'Packet'), 
            ('icmp', 'ICMP'),
            ('icmp6', 'ICMP6')
        ]
        
        for protocol_key, protocol_name in extended_protocols:
            if protocol_key in stats and stats[protocol_key]:
                in_use_value = stats[protocol_key].get('in_use', 0)
                if in_use_value > 0:
                    lines.append(f"{protocol_name}:")
                    for key, value in stats[protocol_key].items():
                        if value is not None:
                            lines.append(f"  {key.replace('_', ' ').title():<12} {value}")
                    lines.append("")
        
        if 'tcp_ext' in stats and stats['tcp_ext']:
            lines.append("TCP Extended Statistics:")
            lines.append("-----------------------")
            for key, value in stats['tcp_ext'].items():
                if value is not None:
                    lines.append(f"  {key:<20} {value}")
            lines.append("")
        
        return lines

    def show_performance_metrics(self) -> None:
        end_time = time.time()
        execution_time = round(end_time - self.start_time, 4)
        
        try:
            memory_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            memory_mb = memory_kb / 1024.0
        except AttributeError:
            memory_kb = 0
            memory_mb = 0.0
        
        metrics = {
            'performance': {
                'execution_time_seconds': execution_time,
                'peak_memory_mb': round(memory_mb, 2),
                'peak_memory_kb': memory_kb,
                'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            }
        }
        
        if self.config.json_output:
            output = json.dumps(metrics, indent=2, ensure_ascii=False)
        else:
            output = self.generate_performance_human_readable(metrics)
        
        if self.config.output_file and self.config.json_output:
            self.log_message(LogLevel.INFO, "Performance metrics are included in the main JSON output")
        elif not self.config.quiet:
            print(output)

    def generate_performance_human_readable(self, metrics: Dict[str, Any]) -> str:
        lines = []
        lines.append("")
        lines.append("Performance Metrics:")
        lines.append("===================")
        lines.append(f"Execution time: {metrics['performance']['execution_time_seconds']}s")
        lines.append(f"Peak memory:    {metrics['performance']['peak_memory_mb']} MB")
        lines.append(f"Python version: {metrics['performance']['python_version']}")
        return '\n'.join(lines)

def main() -> None:
    if not sys.stdin.isatty() and len(sys.argv) == 1:
        print("This script must be run from the command line with arguments.", file=sys.stderr)
        sys.exit(1)
    
    app = SocketStatsTool()
    app.run()

if __name__ == '__main__':
    main()
