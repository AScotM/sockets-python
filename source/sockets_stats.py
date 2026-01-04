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
from typing import Dict, List, Any, Optional, Union
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
    def __init__(self):
        self.config = ToolConfig()
        self.start_time = time.time()
        self.max_file_size = 10 * 1024 * 1024

        self.protocol_parsers = {
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
            }),
            'UDP6:': lambda p, s: self.parse_protocol_section(p, s, 'udp6', {
                'inuse': 'in_use', 'mem': 'memory'
            })
        }

    def run(self):
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

    def parse_command_line(self):
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
            self.config.sockstat_path = args.path
        
        if args.performance:
            self.config.show_performance = True
        
        if args.quiet:
            self.config.quiet = True
        
        if args.extended:
            self.config.extended = True
        
        if args.output:
            self.config.output_file = args.output
        
        if args.version:
            if not args.quiet:
                self.show_version()
            sys.exit(0)

    def validate_config(self):
        if not isinstance(self.config.log_level, LogLevel):
            raise RuntimeError(f"Invalid log level configuration")
        
        if '\0' in self.config.sockstat_path or '..' in self.config.sockstat_path:
            raise RuntimeError("Invalid path: potential path traversal attack detected")
        
        if self.config.output_file and ('\0' in self.config.output_file or '..' in self.config.output_file):
            raise RuntimeError("Invalid output file path: potential path traversal attack detected")

    def check_sockstat_file(self):
        path = Path(self.config.sockstat_path)
        
        if path.is_symlink():
            real_path = path.resolve()
            if not real_path.exists():
                raise RuntimeError(f"Cannot resolve symbolic link: {self.config.sockstat_path}")
            self.config.sockstat_path = str(real_path)
            path = real_path
        
        if not path.exists():
            raise RuntimeError(
                f"'{self.config.sockstat_path}' not found. "
                "Ensure you are running on a Linux system or specify --path for an alternate file"
            )
        
        if not os.access(self.config.sockstat_path, os.R_OK):
            raise RuntimeError(f"Cannot read '{self.config.sockstat_path}'")
        
        if path.is_dir():
            raise RuntimeError(f"'{self.config.sockstat_path}' is a directory, expected a file")
        
        try:
            file_size = path.stat().st_size
            if file_size > self.max_file_size:
                self.log_message(LogLevel.WARNING, f"File size {file_size} exceeds threshold {self.max_file_size}")
        except OSError as e:
            raise RuntimeError(f"Cannot access file stats: {str(e)}")

    def log_message(self, level: LogLevel, message: str):
        if level.value < self.config.log_level.value:
            return
        
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted_message = f'[{timestamp}] {level.name}: {message}'
        
        if level == LogLevel.ERROR:
            print(formatted_message, file=sys.stderr)
        elif not self.config.json_output:
            print(formatted_message)

    def show_version(self):
        print("Socket Statistics Tool 1.2.0")
        print(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

    def show_help(self):
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
            'tcp6': {
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
            'udp6': {
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
        
        try:
            with open(self.config.sockstat_path, 'r') as file:
                line_count = 0
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    
                    self.parse_sockstat_line(line, stats)
                    line_count += 1
            
            self.log_message(LogLevel.DEBUG, f"Processed {line_count} lines from sockstat file")
            
        except PermissionError as e:
            raise RuntimeError(f"Permission denied reading {self.config.sockstat_path}") from e
        except OSError as e:
            raise RuntimeError(f"OS error reading {self.config.sockstat_path}: {str(e)}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to read {self.config.sockstat_path}: {str(e)}") from e

        if self.config.extended:
            self.load_extended_protocol_info(stats)
        
        return stats

    def initialize_extended_stats(self, stats: Dict[str, Any]):
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

    def parse_sockstat_line(self, line: str, stats: Dict[str, Any]):
        parts = line.split()
        if len(parts) < 2:
            self.log_message(LogLevel.DEBUG, f"Skipping malformed line: {line}")
            return
        
        section = parts[0]
        
        if section in self.protocol_parsers:
            self.protocol_parsers[section](parts, stats)
        else:
            self.log_message(LogLevel.DEBUG, f"Unknown section: {section}")

    def parse_sockets_section(self, parts: List[str], stats: Dict[str, Any]):
        if len(parts) >= 3:
            parsed_value = self.parse_int(parts[2])
            if parsed_value is not None:
                stats['sockets_used'] = parsed_value

    def load_extended_protocol_info(self, stats: Dict[str, Any]):
        self.load_unix_sockets(stats)
        self.load_netlink_sockets(stats)
        self.load_packet_sockets(stats)
        self.load_icmp_info(stats)
        self.load_additional_network_stats(stats)

    def load_unix_sockets(self, stats: Dict[str, Any]):
        unix_path = '/proc/net/unix'
        if self.check_file_access(unix_path):
            try:
                with open(unix_path, 'r') as file:
                    unix_count = 0
                    file.readline()
                    
                    for line in file:
                        if line.strip():
                            unix_count += 1
                    
                    stats['unix']['in_use'] = unix_count
                    
            except Exception as e:
                self.log_message(LogLevel.DEBUG, f"Could not read UNIX socket info: {str(e)}")

    def load_netlink_sockets(self, stats: Dict[str, Any]):
        netlink_path = '/proc/net/netlink'
        if self.check_file_access(netlink_path):
            try:
                with open(netlink_path, 'r') as file:
                    netlink_count = 0
                    file.readline()
                    
                    for line in file:
                        if line.strip():
                            netlink_count += 1
                    
                    stats['netlink']['in_use'] = netlink_count
                    
            except Exception as e:
                self.log_message(LogLevel.DEBUG, f"Could not read netlink socket info: {str(e)}")

    def load_packet_sockets(self, stats: Dict[str, Any]):
        packet_path = '/proc/net/packet'
        if self.check_file_access(packet_path):
            try:
                with open(packet_path, 'r') as file:
                    packet_count = 0
                    file.readline()
                    
                    for line in file:
                        if line.strip():
                            packet_count += 1
                    
                    stats['packet']['in_use'] = packet_count
                    
            except Exception as e:
                self.log_message(LogLevel.DEBUG, f"Could not read packet socket info: {str(e)}")

    def load_icmp_info(self, stats: Dict[str, Any]):
        snmp_path = '/proc/net/snmp'
        if self.check_file_access(snmp_path):
            try:
                with open(snmp_path, 'r') as file:
                    in_icmp_line = False
                    in_icmp6_line = False
                    
                    for line in file:
                        line = line.strip()
                        
                        if line.startswith('Icmp:'):
                            in_icmp_line = True
                            continue
                        elif line.startswith('Icmp6:'):
                            in_icmp6_line = True
                            continue
                        
                        if in_icmp_line:
                            parts = line.split()
                            if parts:
                                parsed_value = self.parse_int(parts[0])
                                if parsed_value is not None:
                                    stats['icmp']['in_use'] = parsed_value
                            in_icmp_line = False
                        
                        if in_icmp6_line:
                            parts = line.split()
                            if parts:
                                parsed_value = self.parse_int(parts[0])
                                if parsed_value is not None:
                                    stats['icmp6']['in_use'] = parsed_value
                            in_icmp6_line = False
                    
            except Exception as e:
                self.log_message(LogLevel.DEBUG, f"Could not read ICMP info: {str(e)}")

    def load_additional_network_stats(self, stats: Dict[str, Any]):
        netstat_path = '/proc/net/netstat'
        if self.check_file_access(netstat_path):
            try:
                with open(netstat_path, 'r') as file:
                    for line in file:
                        line = line.strip()
                        if line.startswith('TcpExt:'):
                            self.parse_tcp_extended_stats(line, stats)
                    
            except Exception as e:
                self.log_message(LogLevel.DEBUG, f"Could not read extended network stats: {str(e)}")

    def check_file_access(self, file_path: str) -> bool:
        path = Path(file_path)
        return path.exists() and os.access(file_path, os.R_OK)

    def parse_tcp_extended_stats(self, line: str, stats: Dict[str, Any]):
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
                              protocol: str, mapping: Dict[str, str]):
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

    def display_stats(self, stats: Dict[str, Any]):
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
            ('tcp6', 'TCP6'),
            ('udp', 'UDP'),
            ('udp6', 'UDP6'),
            ('udp_lite', 'UDPLite'),
            ('raw', 'RAW'),
            ('frag', 'FRAG')
        ]
        
        for protocol_key, protocol_name in protocols:
            if protocol_key in stats:
                has_values = any(value is not None for value in stats[protocol_key].values())
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
            if protocol_key in stats:
                in_use_value = stats[protocol_key].get('in_use')
                if in_use_value is not None and in_use_value > 0:
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

    def show_performance_metrics(self):
        end_time = time.time()
        execution_time = round(end_time - self.start_time, 4)
        
        memory_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        memory_mb = memory_kb / 1024.0
        
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

def main():
    if not sys.stdin.isatty() and len(sys.argv) == 1:
        print("This script must be run from the command line with arguments.", file=sys.stderr)
        sys.exit(1)
    
    app = SocketStatsTool()
    app.run()

if __name__ == '__main__':
    main()
