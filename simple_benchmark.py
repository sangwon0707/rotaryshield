#!/usr/bin/env python3
"""
RotaryShield Simple Performance Benchmark
Focus on pattern matching and core system performance validation.
"""

import time
import sys
import statistics
import psutil
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from rotaryshield.monitoring.pattern_matcher import PatternMatcher
from rotaryshield.utils.validators import validate_ip_address, sanitize_string


def benchmark_pattern_matching():
    """Benchmark core pattern matching performance."""
    print("🚀 RotaryShield Pattern Matching Benchmark")
    print("=" * 50)
    
    # Initialize pattern matcher
    matcher = PatternMatcher()
    
    # Add realistic security patterns
    patterns = {
        'ssh_fail': r'Failed password.*from (\d+\.\d+\.\d+\.\d+)',
        'nginx_404': r'GET .* HTTP/1\.[01]" 404.*(\d+\.\d+\.\d+\.\d+)',
        'apache_error': r'\[error\].*client (\d+\.\d+\.\d+\.\d+)',
        'ftp_fail': r'AUTHENTICATION FAILED.*(\d+\.\d+\.\d+\.\d+)',
    }
    
    successful_patterns = 0
    for name, pattern in patterns.items():
        if matcher.add_pattern(name, pattern):
            successful_patterns += 1
            print(f"✅ Added pattern: {name}")
        else:
            print(f"❌ Failed to add pattern: {name}")
    
    print(f"\n📊 Successfully added {successful_patterns}/{len(patterns)} patterns")
    
    # Create test log entries
    test_logs = [
        "Jan 30 10:30:15 server sshd[1234]: Failed password for user from 192.168.1.100 port 22 ssh2",
        "Jan 30 10:30:16 server nginx: 192.168.1.101 - - [30/Jan/2025:10:30:16] GET /admin HTTP/1.1 404 192.168.1.101",
        "Jan 30 10:30:17 server apache: [error] [client 192.168.1.102] File does not exist",
        "Jan 30 10:30:18 server ftpd: AUTHENTICATION FAILED for user admin 192.168.1.103",
        "Jan 30 10:30:19 server postfix: Normal message without threats",
        "Jan 30 10:30:20 server kernel: System boot message",
    ]
    
    # Warm-up runs
    print("\n🔥 Warming up...")
    for _ in range(1000):
        for log in test_logs:
            matcher.match_line(log)
    
    # Performance benchmark
    print("📊 Running performance benchmark...")
    iterations = 10000
    
    start_time = time.perf_counter()
    match_count = 0
    
    for i in range(iterations):
        for log in test_logs:
            matches = matcher.match_line(log)
            match_count += len(matches)
    
    end_time = time.perf_counter()
    
    # Calculate metrics
    total_operations = iterations * len(test_logs)
    duration = end_time - start_time
    ops_per_second = total_operations / duration
    avg_latency_ms = (duration / total_operations) * 1000
    
    print(f"\n📈 Performance Results:")
    print(f"Total operations: {total_operations:,}")
    print(f"Duration: {duration:.2f} seconds") 
    print(f"Operations per second: {ops_per_second:,.0f}")
    print(f"Average latency: {avg_latency_ms:.3f} ms")
    print(f"Total matches found: {match_count:,}")
    
    # Performance targets
    target_ops_per_sec = 5000
    target_latency_ms = 1.0
    
    ops_pass = ops_per_second >= target_ops_per_sec
    latency_pass = avg_latency_ms <= target_latency_ms
    
    print(f"\n🎯 Performance Target Validation:")
    print(f"Operations/sec target (≥{target_ops_per_sec:,}): {'✅ PASS' if ops_pass else '❌ FAIL'}")
    print(f"Latency target (≤{target_latency_ms}ms): {'✅ PASS' if latency_pass else '❌ FAIL'}")
    
    return ops_per_second, avg_latency_ms


def benchmark_redos_protection():
    """Benchmark ReDoS protection effectiveness."""
    print("\n🛡️ ReDoS Protection Benchmark")
    print("=" * 50)
    
    matcher = PatternMatcher()
    
    # Test malicious patterns that should be rejected
    malicious_patterns = [
        ("Catastrophic Backtracking 1", r"(a+)+"),
        ("Catastrophic Backtracking 2", r"(a*)*"),
        ("Nested Quantifiers", r"(a+)+(b+)+"),
        ("Alternation Bomb", r"(a|a)*"),
        ("Complex Email Pattern", r"^([a-zA-Z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})$"),
    ]
    
    rejected_count = 0
    total_patterns = len(malicious_patterns)
    
    for name, pattern in malicious_patterns:
        start_time = time.perf_counter()
        success = matcher.add_pattern(f"test_{name.lower().replace(' ', '_')}", pattern)
        end_time = time.perf_counter()
        
        response_time = (end_time - start_time) * 1000
        
        if not success:
            rejected_count += 1
            print(f"✅ Rejected {name}: {response_time:.3f}ms")
        else:
            print(f"❌ Accepted {name}: SECURITY RISK! ({response_time:.3f}ms)")
    
    protection_rate = (rejected_count / total_patterns) * 100
    
    print(f"\n🛡️ Protection Results:")
    print(f"Patterns tested: {total_patterns}")
    print(f"Patterns rejected: {rejected_count}")
    print(f"Protection rate: {protection_rate:.1f}%")
    
    target_protection = 95.0
    protection_pass = protection_rate >= target_protection
    
    print(f"Protection target (≥{target_protection}%): {'✅ PASS' if protection_pass else '❌ FAIL'}")
    
    return protection_rate


def benchmark_memory_usage():
    """Benchmark memory usage."""
    print("\n📊 Memory Usage Benchmark")
    print("=" * 50)
    
    process = psutil.Process()
    
    def get_memory_mb():
        return process.memory_info().rss / 1024 / 1024
    
    initial_memory = get_memory_mb()
    print(f"Initial memory: {initial_memory:.1f} MB")
    
    # Create pattern matcher with many patterns
    matcher = PatternMatcher()
    
    # Add multiple patterns
    pattern_count = 0
    for i in range(50):  # Reasonable number of patterns
        pattern = f"test{i}_.*from (\\d+\\.\\d+\\.\\d+\\.\\d+)"
        if matcher.add_pattern(f"pattern_{i}", pattern):
            pattern_count += 1
    
    after_patterns_memory = get_memory_mb()
    memory_increase = after_patterns_memory - initial_memory
    
    print(f"After {pattern_count} patterns: {after_patterns_memory:.1f} MB (+{memory_increase:.1f} MB)")
    
    # Process many log lines
    test_log = "Jan 30 10:30:15 server test: Test message from 192.168.1.100"
    for _ in range(5000):
        matcher.match_line(test_log)
    
    final_memory = get_memory_mb()
    total_increase = final_memory - initial_memory
    
    print(f"After 5K matches: {final_memory:.1f} MB (+{total_increase:.1f} MB total)")
    
    # Memory target check
    memory_target = 50.0  # 50MB target
    memory_pass = final_memory < memory_target
    
    print(f"Memory target (<{memory_target} MB): {'✅ PASS' if memory_pass else '❌ FAIL'}")
    
    return final_memory


def benchmark_input_validation():
    """Benchmark input validation performance."""
    print("\n🔍 Input Validation Benchmark")
    print("=" * 50)
    
    # Test IP validation
    test_ips = ["192.168.1.100", "10.0.0.1", "172.16.0.1", "invalid.ip", "127.0.0.1"]
    iterations = 10000
    
    start_time = time.perf_counter()
    valid_count = 0
    
    for _ in range(iterations):
        for ip in test_ips:
            is_valid, _, _ = validate_ip_address(ip)
            if is_valid:
                valid_count += 1
    
    end_time = time.perf_counter()
    
    duration = end_time - start_time
    total_validations = iterations * len(test_ips)
    validations_per_sec = total_validations / duration
    
    print(f"IP Validation: {validations_per_sec:,.0f} validations/sec")
    
    # Test string sanitization
    test_strings = [
        "Normal string",
        "String with special chars !@#$%^&*()",
        "SQL injection attempt: SELECT * FROM users; DROP TABLE users;",
        "Shell injection: ; rm -rf /",
        "x" * 1000  # Long string
    ]
    
    start_time = time.perf_counter()
    
    for _ in range(iterations):
        for test_str in test_strings:
            sanitized = sanitize_string(test_str)
    
    end_time = time.perf_counter()
    
    duration = end_time - start_time
    total_sanitizations = iterations * len(test_strings)
    sanitizations_per_sec = total_sanitizations / duration
    
    print(f"String Sanitization: {sanitizations_per_sec:,.0f} sanitizations/sec")
    
    return validations_per_sec, sanitizations_per_sec


def main():
    """Run all benchmarks."""
    try:
        print("🚀 Starting RotaryShield Performance Benchmarks")
        print("=" * 60)
        
        # Pattern matching benchmark
        ops_per_sec, latency = benchmark_pattern_matching()
        
        # ReDoS protection benchmark  
        protection_rate = benchmark_redos_protection()
        
        # Memory usage benchmark
        memory_usage = benchmark_memory_usage()
        
        # Input validation benchmark
        ip_val_rate, str_san_rate = benchmark_input_validation()
        
        # Summary
        print("\n" + "=" * 60)
        print("📋 BENCHMARK SUMMARY")
        print("=" * 60)
        
        print(f"Pattern Matching: {ops_per_sec:,.0f} ops/sec, {latency:.3f}ms latency")
        print(f"ReDoS Protection: {protection_rate:.1f}% effective")
        print(f"Memory Usage: {memory_usage:.1f} MB peak")
        print(f"IP Validation: {ip_val_rate:,.0f}/sec")
        print(f"String Sanitization: {str_san_rate:,.0f}/sec")
        
        # Overall assessment
        overall_pass = (
            ops_per_sec >= 5000 and
            latency <= 1.0 and
            protection_rate >= 95.0 and
            memory_usage < 50.0
        )
        
        print(f"\n🎯 Overall Performance: {'✅ PASS' if overall_pass else '❌ NEEDS IMPROVEMENT'}")
        
        if overall_pass:
            print("🚀 RotaryShield meets all performance targets!")
        else:
            print("⚠️  Some performance targets not met. Review results above.")
            
    except KeyboardInterrupt:
        print("\n🛑 Benchmark interrupted by user")
    except Exception as e:
        print(f"\n❌ Benchmark failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())