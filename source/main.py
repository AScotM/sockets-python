#!/usr/bin/env python3

import os
import sys
import json
import time
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

class SocketStatsTool:
    def __init__(self):
        self.sockstat_path = '/proc/net/sockstat'
        self.log_levels = {
            'DEBUG': 0,
            'INFO': 1,
            'WARNING': 2,
            'ERROR': 3
        }
        
        self.config = {
            'log_level': 'INFO',
            'json_output': False,
            'help': False,
            'show_performance': False,
            'quiet': False,
            'extended': False
        }
        
        self.start_time = time.time()
        self.extended_mode = False

    def run(self):
        try:
            self.parse_command_line()
            
            if self.config['help']:
                self.show_help()
                sys.exit(0)
            
            self.validate_config()
            self.check_sockstat_file()
            
            stats = self.get_socket_stats()
            
            if not self.config['quiet']:
                self.display_stats(stats)

            if self.config['show_performance']:
                self.show_performance_metrics()
            
            sys.exit(0)
            
        except Exception as e:
            self.log_message('ERROR', str(e))
            sys.exit(1)

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
        
        args = parser.parse_args()
        
        if args.json:
            self.config['json_output'] = True
        
        if args.log_level:
            self.config['log_level'] = args.log_level.upper()
        
        if args.help:
            self.config['help'] = True
        
        if args.path:
            self.sockstat_path = args.path
        
        if args.performance:
            self.config['show_performance'] = True
        
        if args.quiet:
            self.config['quiet'] = True
        
        if args.extended:
            self.config['extended'] = True
            self.extended_mode = True
        
        if args.version:
            self.show_version()
            sys.exit(0)

    def validate_config(self):
        if self.config['log_level'] not in self.log_levels:
            raise RuntimeError(
                f"Invalid log level: {self.config['log_level']}. "
                f"Valid levels: {', '.join(self.log_levels.keys())}"
            )
        
        if '\0' in self.sockstat_path:
            raise RuntimeError("Invalid path: contains null byte")

    def check_sockstat_file(self):
        path = Path(self.sockstat_path)
        
        if path.is_symlink():
            real_path = path.resolve()
            if not real_path.exists():
                raise RuntimeError(f"Cannot resolve symbolic link: {self.sockstat_path}")
            self.sockstat_path = str(real_path)
            path = real_path
        
        if not path.exists():
            raise RuntimeError(
                f"'{self.sockstat_path}' not found. "
                "Ensure you are running on a Linux system or specify --path for an alternate file"
            )
        
        if not os.access(self.sockstat_path, os.R_OK):
            raise RuntimeError(f"Cannot read '{self.sockstat_path}'")
        
        if path.is_dir():
            raise RuntimeError(f"'{self.sockstat_path}' is a directory, expected a file")

    def log_message(self, level: str, message: str):
        msg_level = self.log_levels.get(level, self.log_levels['INFO'])
        conf_level = self.log_levels[self.config['log_level']]
        
        if msg_level < conf_level:
            return
        
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted_message = f'[{timestamp}] {level}: {message}'
        
        if self.config['json_output'] or level == 'ERROR':
            print(formatted_message, file=sys.stderr)
        else:
            print(formatted_message)

    def show_version(self):
        print("Socket Statistics Tool 1.1.0")
        print(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

    def show_help(self):
        help_text = """Socket Statistics Tool 1.1.0

Usage: socket_stats.py [OPTIONS]

Options:
  --json                 Output socket summary in JSON format
  --log-level LEVEL      Set log level (DEBUG, INFO, WARNING, ERROR)
  --path PATH            Path to sockstat file (default: /proc/net/sockstat)
  --performance          Show performance metrics
  --quiet                Suppress all non-error output
  --extended             Show extended protocol information
  --version              Display version information
  --help                 Display this help message

Examples:
  socket_stats.py --json
  socket_stats.py --log-level DEBUG
  socket_stats.py --json --log-level WARNING
  socket_stats.py --path /tmp/test-sockstat --json
  socket_stats.py --performance --json
  socket_stats.py --quiet --json
  socket_stats.py --extended --json

"""
        print(help_text)

    def get_socket_stats(self) -> Dict[str, Any]:
        self.log_message('INFO', f"Reading socket statistics from {self.sockstat_path}")
        
        stats = {
            'metadata': {
                'source': self.sockstat_path,
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

        if self.extended_mode:
            self.initialize_extended_stats(stats)
        
        try:
            with open(self.sockstat_path, 'r') as file:
                line_count = 0
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    
                    self.parse_line(line, stats)
                    line_count += 1
            
            self.log_message('DEBUG', f"Processed {line_count} lines from sockstat file")
            
        except Exception as e:
            raise RuntimeError(f"Failed to read {self.sockstat_path}: {str(e)}")

        if self.extended_mode:
            self.load_extended_protocol_info(stats)
        
        return stats

    def initialize_extended_stats(self, stats: Dict[str, Any]):
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
        
        stats['unix'] = {
            'in_use': 0,
            'dynamic': 0,
            'inode': 0
        }
        
        stats['icmp'] = {
            'inuse': 0
        }
        
        stats['icmp6'] = {
            'inuse': 0
        }
        
        stats['netlink'] = {
            'in_use': 0
        }
        
        stats['packet'] = {
            'in_use': 0,
            'memory': 0
        }

    def parse_line(self, line: str, stats: Dict[str, Any]):
        parts = line.split()
        if len(parts) < 2:
            self.log_message('DEBUG', f"Skipping malformed line: {line}")
            return
        
        section = parts[0]
        
        if section == 'sockets:':
            if len(parts) >= 3:
                stats['sockets_used'] = self.parse_int(parts[2])
        
        elif section == 'TCP:':
            self.parse_protocol_section(parts, stats, 'tcp', {
                'inuse': 'in_use',
                'orphan': 'orphan',
                'tw': 'time_wait',
                'alloc': 'allocated',
                'mem': 'memory'
            })
        
        elif section == 'UDP:':
            self.parse_protocol_section(parts, stats, 'udp', {
                'inuse': 'in_use',
                'mem': 'memory'
            })
        
        elif section == 'UDPLITE:':
            self.parse_protocol_section(parts, stats, 'udp_lite', {
                'inuse': 'in_use'
            })
        
        elif section == 'RAW:':
            self.parse_protocol_section(parts, stats, 'raw', {
                'inuse': 'in_use'
            })
        
        elif section == 'FRAG:':
            self.parse_protocol_section(parts, stats, 'frag', {
                'inuse': 'in_use',
                'memory': 'memory'
            })
        
        elif section == 'TCP6:' and self.extended_mode:
            self.parse_protocol_section(parts, stats, 'tcp6', {
                'inuse': 'in_use',
                'orphan': 'orphan',
                'tw': 'time_wait',
                'alloc': 'allocated',
                'mem': 'memory'
            })
        
        elif section == 'UDP6:' and self.extended_mode:
            self.parse_protocol_section(parts, stats, 'udp6', {
                'inuse': 'in_use',
                'mem': 'memory'
            })
        
        else:
            self.log_message('DEBUG', f"Unknown section: {section}")

    def load_extended_protocol_info(self, stats: Dict[str, Any]):
        self.load_unix_sockets(stats)
        self.load_netlink_sockets(stats)
        self.load_packet_sockets(stats)
        self.load_icmp_info(stats)
        self.load_additional_network_stats(stats)

    def load_unix_sockets(self, stats: Dict[str, Any]):
        sockstat6_path = '/proc/net/sockstat6'
        if os.path.exists(sockstat6_path) and os.access(sockstat6_path, os.R_OK):
            try:
                with open(sockstat6_path, 'r') as file:
                    for line in file:
                        line = line.strip()
                        if line.startswith('UNIX:'):
                            parts = line.split()
                            self.parse_protocol_section(parts, stats, 'unix', {
                                'inuse': 'in_use',
                                'dynamic': 'dynamic',
                                'inode': 'inode'
                            })
                            break
            except Exception as e:
                self.log_message('DEBUG', f"Could not read UNIX socket info: {str(e)}")

    def load_netlink_sockets(self, stats: Dict[str, Any]):
        netlink_path = '/proc/net/netlink'
        if os.path.exists(netlink_path) and os.access(netlink_path, os.R_OK):
            try:
                with open(netlink_path, 'r') as file:
                    netlink_count = 0
                    file.readline()  # Skip header
                    
                    for line in file:
                        line = line.strip()
                        if line:
                            netlink_count += 1
                    
                    stats['netlink']['in_use'] = netlink_count
                    
            except Exception as e:
                self.log_message('DEBUG', f"Could not read netlink socket info: {str(e)}")

    def load_packet_sockets(self, stats: Dict[str, Any]):
        packet_path = '/proc/net/packet'
        if os.path.exists(packet_path) and os.access(packet_path, os.R_OK):
            try:
                with open(packet_path, 'r') as file:
                    packet_count = 0
                    file.readline()  # Skip header
                    
                    for line in file:
                        line = line.strip()
                        if line:
                            packet_count += 1
                    
                    stats['packet']['in_use'] = packet_count
                    
            except Exception as e:
                self.log_message('DEBUG', f"Could not read packet socket info: {str(e)}")

    def load_icmp_info(self, stats: Dict[str, Any]):
        snmp_path = '/proc/net/snmp'
        if os.path.exists(snmp_path) and os.access(snmp_path, os.R_OK):
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
                                stats['icmp']['inuse'] = self.parse_int(parts[0])
                            in_icmp_line = False
                        
                        if in_icmp6_line:
                            parts = line.split()
                            if parts:
                                stats['icmp6']['inuse'] = self.parse_int(parts[0])
                            in_icmp6_line = False
                    
            except Exception as e:
                self.log_message('DEBUG', f"Could not read ICMP info: {str(e)}")

    def load_additional_network_stats(self, stats: Dict[str, Any]):
        netstat_path = '/proc/net/netstat'
        if os.path.exists(netstat_path) and os.access(netstat_path, os.R_OK):
            try:
                with open(netstat_path, 'r') as file:
                    for line in file:
                        line = line.strip()
                        
                        if line.startswith('TcpExt:'):
                            self.parse_tcp_extended_stats(line, stats)
                    
            except Exception as e:
                self.log_message('DEBUG', f"Could not read extended network stats: {str(e)}")

    def parse_tcp_extended_stats(self, line: str, stats: Dict[str, Any]):
        if not self.extended_mode:
            return
        
        parts = line.split()
        if len(parts) < 2:
            return
        
        stats['tcp_ext'] = {}
        
        for i in range(1, len(parts), 2):
            if i + 1 >= len(parts):
                break
            
            key = parts[i]
            value = parts[i + 1]
            
            stats['tcp_ext'][key] = self.parse_int(value)

    def parse_protocol_section(self, parts: List[str], stats: Dict[str, Any], protocol: str, mapping: Dict[str, str]):
        for i in range(1, len(parts), 2):
            if i + 1 >= len(parts):
                break
            
            key = parts[i]
            value = parts[i + 1]
            
            if key in mapping:
                stats[protocol][mapping[key]] = self.parse_int(value)
            else:
                self.log_message('DEBUG', f"Unknown {protocol} field: {key}")

    def parse_int(self, value: str) -> int:
        try:
            return int(value)
        except ValueError:
            self.log_message('WARNING', f"Failed to parse integer: '{value}'")
            return 0

    def display_stats(self, stats: Dict[str, Any]):
        if self.config['json_output']:
            self.output_json(stats)
        else:
            self.output_human_readable(stats)

    def output_json(self, stats: Dict[str, Any]):
        try:
            json_data = json.dumps(stats, indent=2, ensure_ascii=False)
            print(json_data)
        except Exception as e:
            raise RuntimeError(f'Failed to encode JSON: {str(e)}')

    def output_human_readable(self, stats: Dict[str, Any]):
        print("Socket Statistics")
        print("=================")
        print(f"Generated: {stats['metadata']['generated_at']}")
        print(f"Hostname:  {stats['metadata']['hostname']}")
        print(f"Source:    {stats['metadata']['source']}")
        print()
        
        print(f"Sockets used: {stats['sockets_used']}")
        print()
        
        print("TCP:")
        print(f"  In use:     {stats['tcp']['in_use']}")
        print(f"  Orphan:     {stats['tcp']['orphan']}")
        print(f"  Time wait:  {stats['tcp']['time_wait']}")
        print(f"  Allocated:  {stats['tcp']['allocated']}")
        print(f"  Memory:     {stats['tcp']['memory']} pages")
        print()
        
        print("UDP:")
        print(f"  In use:     {stats['udp']['in_use']}")
        print(f"  Memory:     {stats['udp']['memory']} pages")
        print()
        
        print("UDPLite:")
        print(f"  In use:     {stats['udp_lite']['in_use']}")
        print()
        
        print("RAW:")
        print(f"  In use:     {stats['raw']['in_use']}")
        print()
        
        print("FRAG:")
        print(f"  In use:     {stats['frag']['in_use']}")
        print(f"  Memory:     {stats['frag']['memory']} pages")

        if self.extended_mode:
            self.output_extended_human_readable(stats)

    def output_extended_human_readable(self, stats: Dict[str, Any]):
        print()
        print("Extended Protocol Information:")
        print("=============================")
        
        if 'tcp6' in stats and stats['tcp6']['in_use'] > 0:
            print("TCP6:")
            print(f"  In use:     {stats['tcp6']['in_use']}")
            print(f"  Orphan:     {stats['tcp6']['orphan']}")
            print(f"  Time wait:  {stats['tcp6']['time_wait']}")
            print(f"  Allocated:  {stats['tcp6']['allocated']}")
            print(f"  Memory:     {stats['tcp6']['memory']} pages")
            print()
        
        if 'udp6' in stats and stats['udp6']['in_use'] > 0:
            print("UDP6:")
            print(f"  In use:     {stats['udp6']['in_use']}")
            print(f"  Memory:     {stats['udp6']['memory']} pages")
            print()
        
        if 'unix' in stats and stats['unix']['in_use'] > 0:
            print("UNIX:")
            print(f"  In use:     {stats['unix']['in_use']}")
            print(f"  Dynamic:    {stats['unix']['dynamic']}")
            print(f"  Inode:      {stats['unix']['inode']}")
            print()
        
        if 'netlink' in stats and stats['netlink']['in_use'] > 0:
            print("Netlink:")
            print(f"  In use:     {stats['netlink']['in_use']}")
            print()
        
        if 'packet' in stats and stats['packet']['in_use'] > 0:
            print("Packet:")
            print(f"  In use:     {stats['packet']['in_use']}")
            print()
        
        if 'icmp' in stats and stats['icmp']['inuse'] > 0:
            print("ICMP:")
            print(f"  In use:     {stats['icmp']['inuse']}")
            print()
        
        if 'icmp6' in stats and stats['icmp6']['inuse'] > 0:
            print("ICMP6:")
            print(f"  In use:     {stats['icmp6']['inuse']}")
            print()

    def show_performance_metrics(self):
        end_time = time.time()
        execution_time = round(end_time - self.start_time, 4)
        memory_usage = round(sys.getsizeof(self) / 1024 / 1024, 2)
        
        metrics = {
            'performance': {
                'execution_time_seconds': execution_time,
                'peak_memory_mb': memory_usage,
                'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            }
        }
        
        if self.config['json_output']:
            print(json.dumps(metrics, indent=2, ensure_ascii=False))
        else:
            print()
            print("Performance Metrics:")
            print("===================")
            print(f"Execution time: {execution_time}s")
            print(f"Peak memory:    {memory_usage} MB")
            print(f"Python version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

def main():
    if not sys.stdin.isatty():
        print("This script must be run from the command line.")
        sys.exit(1)
    
    app = SocketStatsTool()
    app.run()

if __name__ == '__main__':
    main()
