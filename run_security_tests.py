#!/usr/bin/env python3
"""
RotaryShield Security Test Runner
Comprehensive security test execution and reporting script.

This script runs all security tests and generates a summary report.
"""

import subprocess
import sys
import time
import json
from pathlib import Path


def run_test_suite(test_path, test_name):
    """Run a specific test suite and return results."""
    print(f"\n🔍 Running {test_name}...")
    print("=" * 60)
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', test_path, '-v', '--tb=short'],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        execution_time = time.time() - start_time
        
        # Parse results
        output_lines = result.stdout.split('\n')
        summary_line = None
        for line in reversed(output_lines):
            if 'failed' in line or 'passed' in line:
                if '=' in line and ('failed' in line or 'passed' in line):
                    summary_line = line.strip()
                    break
        
        if summary_line:
            print(f"✅ {summary_line}")
        else:
            print(f"⚠️  Test completed but summary unclear")
            
        print(f"⏱️  Execution time: {execution_time:.2f} seconds")
        
        return {
            'name': test_name,
            'success': result.returncode == 0,
            'execution_time': execution_time,
            'summary': summary_line or "No summary available",
            'stdout': result.stdout,
            'stderr': result.stderr
        }
        
    except subprocess.TimeoutExpired:
        print(f"❌ {test_name} timed out after 5 minutes")
        return {
            'name': test_name,
            'success': False,
            'execution_time': 300,
            'summary': "Test timed out",
            'stdout': "",
            'stderr': "Timeout"
        }
        
    except Exception as e:
        print(f"❌ Error running {test_name}: {e}")
        return {
            'name': test_name,
            'success': False,
            'execution_time': 0,
            'summary': f"Error: {e}",
            'stdout': "",
            'stderr': str(e)
        }


def main():
    """Main security test execution."""
    print("🛡️  RotaryShield Security Test Suite")
    print("=" * 60)
    print("Comprehensive security testing and vulnerability assessment")
    print("Date:", time.strftime("%Y-%m-%d %H:%M:%S"))
    print()
    
    # Define test suites
    test_suites = [
        ('tests/unit/test_validators.py', 'Input Validation Security Tests'),
        ('tests/unit/test_pattern_matcher.py', 'Pattern Matcher Security Tests'),
        ('tests/security/test_redos_vulnerabilities.py', 'ReDoS Vulnerability Tests'),
        ('tests/security/test_injection_attacks.py', 'Injection Attack Prevention Tests'),
        ('tests/security/test_cli_security.py', 'CLI Security Tests'),
        ('tests/security/test_penetration_testing.py', 'Penetration Testing Suite'),
    ]
    
    results = []
    total_start_time = time.time()
    
    # Run each test suite
    for test_path, test_name in test_suites:
        if Path(test_path).exists():
            result = run_test_suite(test_path, test_name)
            results.append(result)
        else:
            print(f"⚠️  Test file not found: {test_path}")
            results.append({
                'name': test_name,
                'success': False,
                'execution_time': 0,
                'summary': "Test file not found",
                'stdout': "",
                'stderr': f"File not found: {test_path}"
            })
    
    total_execution_time = time.time() - total_start_time
    
    # Generate summary report
    print("\n" + "=" * 60)
    print("🔍 SECURITY TEST SUMMARY REPORT")
    print("=" * 60)
    
    passed_tests = sum(1 for r in results if r['success'])
    total_tests = len(results)
    
    print(f"📊 Overall Results: {passed_tests}/{total_tests} test suites passed")
    print(f"⏱️  Total execution time: {total_execution_time:.2f} seconds")
    print()
    
    # Detailed results
    print("📋 Detailed Results:")
    print("-" * 40)
    
    for result in results:
        status = "✅ PASS" if result['success'] else "❌ FAIL"
        print(f"{status} {result['name']}")
        print(f"    Time: {result['execution_time']:.2f}s")
        print(f"    Summary: {result['summary']}")
        
        if not result['success'] and result['stderr']:
            print(f"    Error: {result['stderr'][:200]}...")
        print()
    
    # Security recommendations
    print("🔒 SECURITY ASSESSMENT:")
    print("-" * 40)
    
    if passed_tests == total_tests:
        print("✅ All security tests passed!")
        print("   System appears ready for production deployment.")
    elif passed_tests >= total_tests * 0.8:
        print("⚠️  Most security tests passed with some issues.")
        print("   Review failed tests before production deployment.")
    elif passed_tests >= total_tests * 0.5:
        print("⚠️  Significant security issues detected.")
        print("   Address failed tests before considering production.")
    else:
        print("❌ Major security vulnerabilities detected.")
        print("   System NOT READY for production deployment.")
        print("   Immediate remediation required.")
    
    print()
    print("📄 Detailed security assessment available in:")
    print("   SECURITY_ASSESSMENT_REPORT.md")
    
    # Save results to JSON
    report_data = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'total_execution_time': total_execution_time,
        'passed_tests': passed_tests,
        'total_tests': total_tests,
        'success_rate': (passed_tests / total_tests) * 100 if total_tests > 0 else 0,
        'results': results
    }
    
    try:
        with open('security_test_results.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        print("   security_test_results.json")
    except Exception as e:
        print(f"⚠️  Could not save JSON report: {e}")
    
    print()
    print("=" * 60)
    
    # Exit with appropriate code
    sys.exit(0 if passed_tests == total_tests else 1)


if __name__ == '__main__':
    main()