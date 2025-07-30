#!/usr/bin/env python3
"""
RotaryShield Performance Benchmark Suite
Comprehensive testing of pattern matching, database operations, and system performance.

This script benchmarks:
- Pattern matching performance with various log patterns
- Database operations (IP bans, queries, statistics)
- Memory usage and CPU consumption
- Concurrent operation performance
- System resource limits validation
"""

import time
import sys
import os
import gc
import threading
import statistics
import psutil
import multiprocessing
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from rotaryshield.monitoring.pattern_matcher import PatternMatcher
from rotaryshield.database.ip_manager import IPManager
from rotaryshield.utils.validators import validate_ip_address, sanitize_string


@dataclass
class BenchmarkResult:
    """Container for benchmark results."""
    test_name: str
    operations_per_second: float
    average_latency_ms: float
    memory_usage_mb: float
    cpu_percent: float
    success_rate: float
    additional_metrics: Dict[str, Any]


class PerformanceBenchmark:
    """Main performance benchmarking class."""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.process = psutil.Process()
        
    def run_all_benchmarks(self) -> None:
        """Execute all performance benchmarks."""
        print("🚀 RotaryShield Performance Benchmark Suite")
        print("=" * 60)
        
        # Pattern matching benchmarks
        self.benchmark_pattern_matching()
        self.benchmark_pattern_compilation()
        self.benchmark_redos_protection()
        
        # Database benchmarks
        self.benchmark_database_operations()
        self.benchmark_concurrent_database()
        
        # Input validation benchmarks
        self.benchmark_input_validation()
        
        # System resource benchmarks
        self.benchmark_memory_usage()
        self.benchmark_concurrent_operations()
        
        # Generate summary report
        self.generate_report()
    
    def benchmark_pattern_matching(self) -> None:
        """Benchmark pattern matching performance."""
        print("\n📊 Pattern Matching Performance")
        print("-" * 40)
        
        # Initialize pattern matcher
        matcher = PatternMatcher()
        
        # Add common log patterns
        patterns = {
            'ssh_fail': r'Failed password.*from (\d+\.\d+\.\d+\.\d+)',
            'nginx_404': r'GET .* HTTP/1\.[01]" 404.*from (\d+\.\d+\.\d+\.\d+)',
            'apache_error': r'\[error\].*client (\d+\.\d+\.\d+\.\d+)',
            'ftp_fail': r'AUTHENTICATION FAILED.*from (\d+\.\d+\.\d+\.\d+)',
            'smtp_relay': r'Relay access denied.*from (\d+\.\d+\.\d+\.\d+)'
        }
        
        for name, pattern in patterns.items():
            matcher.add_pattern(name, pattern)
        
        # Test log lines
        test_logs = [
            "Jan 30 10:30:15 server sshd[1234]: Failed password for user from 192.168.1.100 port 22 ssh2",
            "Jan 30 10:30:16 server nginx: 192.168.1.101 - - [30/Jan/2025:10:30:16] GET /admin HTTP/1.1 404 from 192.168.1.101",
            "Jan 30 10:30:17 server apache: [error] [client 192.168.1.102] File does not exist: /var/www/html/admin",
            "Jan 30 10:30:18 server ftpd: AUTHENTICATION FAILED for user admin from 192.168.1.103",
            "Jan 30 10:30:19 server postfix: Relay access denied from unknown[192.168.1.104]",
            "Jan 30 10:30:20 server kernel: Normal system message without IP",
            "Jan 30 10:30:21 server systemd: Service started successfully"
        ]
        
        # Warm-up
        for _ in range(100):
            for log in test_logs:
                matcher.match_line(log)
        
        # Benchmark
        iterations = 10000
        start_memory = self.get_memory_usage()
        start_time = time.time()
        
        for i in range(iterations):
            for log in test_logs:
                matches = matcher.match_line(log)
        
        end_time = time.time()
        end_memory = self.get_memory_usage()
        
        total_operations = iterations * len(test_logs)
        duration = end_time - start_time
        ops_per_second = total_operations / duration
        avg_latency = (duration / total_operations) * 1000
        
        result = BenchmarkResult(
            test_name="Pattern Matching",
            operations_per_second=ops_per_second,
            average_latency_ms=avg_latency,
            memory_usage_mb=end_memory - start_memory,
            cpu_percent=0,  # Measured separately
            success_rate=100.0,
            additional_metrics={
                "total_patterns": len(patterns),
                "total_operations": total_operations,
                "duration_seconds": duration
            }
        )
        
        self.results.append(result)
        print(f"✅ Pattern matching: {ops_per_second:,.0f} ops/sec, {avg_latency:.2f}ms avg latency")
    
    def benchmark_pattern_compilation(self) -> None:
        """Benchmark pattern compilation performance."""
        print("\n📊 Pattern Compilation Performance")
        print("-" * 40)
        
        # Test patterns with varying complexity
        test_patterns = [
            ("simple", r"test"),
            ("ip_extract", r"from (\d+\.\d+\.\d+\.\d+)"),
            ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            ("log_parse", r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) \[(\w+)\] (.*)$"),
            ("complex", r"^(\d{1,3}\.){3}\d{1,3} - - \[([^\]]+)\] \"([^\"]+)\" (\d+) (\d+)$")
        ]
        
        compilation_times = []
        
        for name, pattern in test_patterns:
            matcher = PatternMatcher()
            
            start_time = time.perf_counter()
            success = matcher.add_pattern(name, pattern)
            end_time = time.perf_counter()
            
            compilation_time = (end_time - start_time) * 1000  # Convert to ms
            compilation_times.append(compilation_time)
            
            status = "✅" if success else "❌"
            print(f"{status} {name}: {compilation_time:.3f}ms")
        
        avg_compilation_time = statistics.mean(compilation_times)
        result = BenchmarkResult(
            test_name="Pattern Compilation",
            operations_per_second=1000 / avg_compilation_time if avg_compilation_time > 0 else 0,
            average_latency_ms=avg_compilation_time,
            memory_usage_mb=0,
            cpu_percent=0,
            success_rate=100.0,
            additional_metrics={
                "patterns_tested": len(test_patterns),
                "fastest_ms": min(compilation_times),
                "slowest_ms": max(compilation_times)
            }
        )
        
        self.results.append(result)
    
    def benchmark_redos_protection(self) -> None:
        """Benchmark ReDoS protection effectiveness."""
        print("\n📊 ReDoS Protection Performance")
        print("-" * 40)
        
        matcher = PatternMatcher()
        
        # Test patterns that should be rejected
        malicious_patterns = [
            ("catastrophic_1", r"(a+)+"),
            ("catastrophic_2", r"(a*)*"),
            ("nested_quantifiers", r"(a+)+(b+)+"),
            ("alternation_bomb", r"(a|a)*"),
        ]
        
        rejection_count = 0
        total_patterns = len(malicious_patterns)
        
        for name, pattern in malicious_patterns:
            start_time = time.perf_counter()
            success = matcher.add_pattern(name, pattern)
            end_time = time.perf_counter()
            
            if not success:
                rejection_count += 1
                print(f"✅ Rejected {name}: {(end_time - start_time)*1000:.3f}ms")
            else:
                print(f"❌ Accepted {name}: SECURITY RISK!")
        
        protection_rate = (rejection_count / total_patterns) * 100
        
        result = BenchmarkResult(
            test_name="ReDoS Protection",
            operations_per_second=0,
            average_latency_ms=0,
            memory_usage_mb=0,
            cpu_percent=0,
            success_rate=protection_rate,
            additional_metrics={
                "patterns_tested": total_patterns,
                "patterns_rejected": rejection_count,
                "protection_rate": protection_rate
            }
        )
        
        self.results.append(result)
        print(f"🛡️ ReDoS protection rate: {protection_rate:.1f}%")
    
    def benchmark_database_operations(self) -> None:
        """Benchmark database operations performance."""
        print("\n📊 Database Operations Performance")
        print("-" * 40)
        
        # Use in-memory database for testing
        ip_manager = IPManager(":memory:")
        
        test_ips = [f"192.168.1.{i}" for i in range(1, 101)]
        
        # Benchmark IP banning
        start_time = time.time()
        for ip in test_ips:
            ip_manager.ban_ip(ip, ban_duration=3600, reason="Benchmark test")
        ban_duration = time.time() - start_time
        
        # Benchmark IP queries
        start_time = time.time()
        for ip in test_ips:
            ip_manager.is_ip_banned(ip)
        query_duration = time.time() - start_time
        
        # Benchmark statistics
        start_time = time.time()
        stats = ip_manager.get_statistics()
        stats_duration = time.time() - start_time
        
        ban_ops_per_sec = len(test_ips) / ban_duration
        query_ops_per_sec = len(test_ips) / query_duration
        
        result = BenchmarkResult(
            test_name="Database Operations",
            operations_per_second=(ban_ops_per_sec + query_ops_per_sec) / 2,
            average_latency_ms=((ban_duration + query_duration) / (len(test_ips) * 2)) * 1000,
            memory_usage_mb=0,
            cpu_percent=0,
            success_rate=100.0,
            additional_metrics={
                "ban_ops_per_sec": ban_ops_per_sec,
                "query_ops_per_sec": query_ops_per_sec,
                "stats_duration_ms": stats_duration * 1000
            }
        )
        
        self.results.append(result)
        print(f"📊 Database: {ban_ops_per_sec:,.0f} bans/sec, {query_ops_per_sec:,.0f} queries/sec")
    
    def benchmark_concurrent_database(self) -> None:
        """Benchmark concurrent database operations."""
        print("\n📊 Concurrent Database Performance")
        print("-" * 40)
        
        ip_manager = IPManager(":memory:")
        
        def worker_thread(thread_id: int, operations: int) -> Tuple[int, float]:
            """Worker thread for concurrent testing."""
            start_time = time.time()
            success_count = 0
            
            for i in range(operations):
                ip = f"10.{thread_id}.1.{i % 255 + 1}"
                try:
                    ip_manager.ban_ip(ip, ban_duration=3600, reason=f"Thread {thread_id} test")
                    success_count += 1
                except Exception:
                    pass
            
            duration = time.time() - start_time
            return success_count, duration
        
        # Test with multiple threads
        num_threads = 10
        operations_per_thread = 100
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(worker_thread, i, operations_per_thread)
                for i in range(num_threads)
            ]
            
            results = [future.result() for future in futures]
        
        total_duration = time.time() - start_time
        total_operations = sum(success for success, _ in results)
        ops_per_second = total_operations / total_duration
        
        result = BenchmarkResult(
            test_name="Concurrent Database",
            operations_per_second=ops_per_second,
            average_latency_ms=(total_duration / total_operations) * 1000,
            memory_usage_mb=0,
            cpu_percent=0,
            success_rate=100.0,
            additional_metrics={
                "num_threads": num_threads,
                "total_operations": total_operations,
                "concurrent_duration": total_duration
            }
        )
        
        self.results.append(result)
        print(f"🔀 Concurrent DB: {ops_per_second:,.0f} ops/sec with {num_threads} threads")
    
    def benchmark_input_validation(self) -> None:
        """Benchmark input validation performance."""
        print("\n📊 Input Validation Performance")
        print("-" * 40)
        
        # Test different validation functions
        test_cases = [
            ("IP validation", lambda: validate_ip_address("192.168.1.100")),
            ("String sanitization", lambda: sanitize_string("Test string with special chars !@#$%")),
            ("Long string sanitization", lambda: sanitize_string("x" * 1000)),
        ]
        
        for test_name, test_func in test_cases:
            iterations = 10000
            
            start_time = time.time()
            for _ in range(iterations):
                test_func()
            duration = time.time() - start_time
            
            ops_per_second = iterations / duration
            avg_latency = (duration / iterations) * 1000
            
            print(f"✅ {test_name}: {ops_per_second:,.0f} ops/sec, {avg_latency:.3f}ms avg")
    
    def benchmark_memory_usage(self) -> None:
        """Benchmark memory usage under load."""
        print("\n📊 Memory Usage Benchmark")
        print("-" * 40)
        
        initial_memory = self.get_memory_usage()
        
        # Create large pattern matcher
        matcher = PatternMatcher()
        
        # Add many patterns
        for i in range(100):
            pattern = f"test{i}_.*from (\\d+\\.\\d+\\.\\d+\\.\\d+)"
            matcher.add_pattern(f"pattern_{i}", pattern)
        
        after_patterns_memory = self.get_memory_usage()
        
        # Process many log lines
        test_log = "Jan 30 10:30:15 server test: Test message from 192.168.1.100"
        for _ in range(10000):
            matcher.match_line(test_log)
        
        final_memory = self.get_memory_usage()
        
        print(f"📈 Initial memory: {initial_memory:.1f}MB")
        print(f"📈 After 100 patterns: {after_patterns_memory:.1f}MB (+{after_patterns_memory - initial_memory:.1f}MB)")
        print(f"📈 After 10K matches: {final_memory:.1f}MB (+{final_memory - initial_memory:.1f}MB)")
        
        # Check if within target limits
        memory_limit = 50.0  # 50MB target
        within_limit = final_memory < memory_limit
        
        print(f"🎯 Memory target (<50MB): {'✅ PASS' if within_limit else '❌ FAIL'}")
    
    def benchmark_concurrent_operations(self) -> None:
        """Benchmark concurrent operations performance."""
        print("\n📊 Concurrent Operations Performance")
        print("-" * 40)
        
        def concurrent_worker(worker_id: int) -> Dict[str, Any]:
            """Worker function for concurrent testing."""
            matcher = PatternMatcher()
            matcher.add_pattern("test", r"test.*from (\d+\.\d+\.\d+\.\d+)")
            
            operations = 1000
            start_time = time.time()
            
            for i in range(operations):
                log_line = f"test message {i} from 192.168.{worker_id}.{i % 255 + 1}"
                matcher.match_line(log_line)
            
            duration = time.time() - start_time
            return {
                "worker_id": worker_id,
                "operations": operations,
                "duration": duration,
                "ops_per_sec": operations / duration
            }
        
        # Test with multiple processes
        num_processes = min(4, multiprocessing.cpu_count())
        
        start_time = time.time()
        
        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            futures = [
                executor.submit(concurrent_worker, i)
                for i in range(num_processes)
            ]
            
            worker_results = [future.result() for future in futures]
        
        total_duration = time.time() - start_time
        total_operations = sum(r["operations"] for r in worker_results)
        total_ops_per_sec = total_operations / total_duration
        
        print(f"🚀 Concurrent processes: {num_processes}")
        print(f"🚀 Total operations: {total_operations:,}")
        print(f"🚀 Total ops/sec: {total_ops_per_sec:,.0f}")
        print(f"🚀 Duration: {total_duration:.2f}s")
    
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        return self.process.memory_info().rss / 1024 / 1024
    
    def generate_report(self) -> None:
        """Generate comprehensive performance report."""
        print("\n" + "=" * 60)
        print("📋 PERFORMANCE BENCHMARK SUMMARY")
        print("=" * 60)
        
        print(f"{'Test Name':<25} {'Ops/Sec':<12} {'Latency(ms)':<12} {'Success%':<10}")
        print("-" * 60)
        
        for result in self.results:
            print(f"{result.test_name:<25} {result.operations_per_second:>10,.0f} "
                  f"{result.average_latency_ms:>10.2f} {result.success_rate:>8.1f}%")
        
        # Performance targets check
        print("\n🎯 Performance Target Validation")
        print("-" * 40)
        
        # Check if pattern matching meets targets
        pattern_result = next((r for r in self.results if r.test_name == "Pattern Matching"), None)
        if pattern_result:
            target_ops = 5000  # 5K ops/sec target
            target_latency = 1.0  # 1ms latency target
            
            ops_pass = pattern_result.operations_per_second >= target_ops
            latency_pass = pattern_result.average_latency_ms <= target_latency
            
            print(f"Pattern matching ops/sec: {'✅ PASS' if ops_pass else '❌ FAIL'} "
                  f"({pattern_result.operations_per_second:,.0f} >= {target_ops:,})")
            print(f"Pattern matching latency: {'✅ PASS' if latency_pass else '❌ FAIL'} "
                  f"({pattern_result.average_latency_ms:.2f}ms <= {target_latency}ms)")
        
        # Check ReDoS protection
        redos_result = next((r for r in self.results if r.test_name == "ReDoS Protection"), None)
        if redos_result:
            protection_target = 95.0  # 95% protection rate target
            protection_pass = redos_result.success_rate >= protection_target
            
            print(f"ReDoS protection rate: {'✅ PASS' if protection_pass else '❌ FAIL'} "
                  f"({redos_result.success_rate:.1f}% >= {protection_target}%)")
        
        print("\n✅ Performance benchmarking complete!")


if __name__ == "__main__":
    try:
        benchmark = PerformanceBenchmark()
        benchmark.run_all_benchmarks()
    except KeyboardInterrupt:
        print("\n🛑 Benchmark interrupted by user")
    except Exception as e:
        print(f"\n❌ Benchmark failed: {e}")
        sys.exit(1)