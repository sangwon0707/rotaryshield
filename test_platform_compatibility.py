#!/usr/bin/env python3
"""
RotaryShield Multi-Platform Compatibility Test Suite
Tests compatibility across different Linux distributions and system configurations.

This script validates:
- Python version compatibility (3.8+)
- Required system packages and dependencies
- Firewall adapter detection and compatibility
- systemd integration compatibility
- File system permissions and paths
- Network capabilities and firewall access
"""

import os
import sys
import subprocess
import platform
import shutil
import importlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import re


@dataclass
class CompatibilityResult:
    """Results of a compatibility test."""
    test_name: str
    passed: bool
    message: str
    details: Dict[str, str]


class PlatformCompatibilityTester:
    """Multi-platform compatibility testing."""
    
    def __init__(self):
        self.results: List[CompatibilityResult] = []
        self.platform_info = self._detect_platform()
        
    def run_all_tests(self) -> bool:
        """Run all compatibility tests."""
        print("🐧 RotaryShield Multi-Platform Compatibility Test")
        print("=" * 60)
        
        # Display platform information
        self._display_platform_info()
        
        # Run compatibility tests
        self._test_python_compatibility()
        self._test_system_dependencies()
        self._test_firewall_compatibility()
        self._test_systemd_compatibility()
        self._test_file_system_compatibility()
        self._test_network_capabilities()
        self._test_rotaryshield_imports()
        
        # Generate compatibility report
        return self._generate_compatibility_report()
    
    def _detect_platform(self) -> Dict[str, str]:
        """Detect current platform and distribution."""
        info = {
            'system': platform.system(),
            'machine': platform.machine(),
            'python_version': platform.python_version(),
            'distribution': 'Unknown',
            'version': 'Unknown',
            'codename': 'Unknown'
        }
        
        # Try to detect Linux distribution
        if os.path.exists('/etc/os-release'):
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release = f.read()
                
                # Parse os-release file
                for line in os_release.split('\n'):
                    if line.startswith('ID='):
                        info['distribution'] = line.split('=')[1].strip('"')
                    elif line.startswith('VERSION_ID='):
                        info['version'] = line.split('=')[1].strip('"')
                    elif line.startswith('VERSION_CODENAME='):
                        info['codename'] = line.split('=')[1].strip('"')
                        
            except Exception as e:
                print(f"Warning: Could not parse /etc/os-release: {e}")
        
        # Additional platform detection
        if os.path.exists('/etc/redhat-release'):
            try:
                with open('/etc/redhat-release', 'r') as f:
                    redhat_info = f.read().strip()
                    info['distribution_details'] = redhat_info
            except Exception:
                pass
                
        return info
    
    def _display_platform_info(self):
        """Display detected platform information."""
        print("🖥️  Platform Information")
        print("-" * 30)
        print(f"System: {self.platform_info['system']}")
        print(f"Architecture: {self.platform_info['machine']}")
        print(f"Python Version: {self.platform_info['python_version']}")
        print(f"Distribution: {self.platform_info['distribution']}")
        print(f"Version: {self.platform_info['version']}")
        if self.platform_info['codename'] != 'Unknown':
            print(f"Codename: {self.platform_info['codename']}")
        print()
    
    def _test_python_compatibility(self):
        """Test Python version and capabilities compatibility."""
        print("🐍 Testing Python Compatibility")
        print("-" * 40)
        
        try:
            # Check Python version
            version_info = sys.version_info
            version_str = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
            
            # RotaryShield requires Python 3.8+
            min_version = (3, 8)
            version_compatible = version_info >= min_version
            
            result = CompatibilityResult(
                test_name="Python Version",
                passed=version_compatible,
                message=f"Python {version_str} ({'compatible' if version_compatible else 'incompatible'})",
                details={
                    'version': version_str,
                    'minimum_required': f"{min_version[0]}.{min_version[1]}",
                    'compatible': str(version_compatible)
                }
            )
            
            self.results.append(result)
            status = "✅" if version_compatible else "❌"
            print(f"{status} Python Version: {version_str} (min: {min_version[0]}.{min_version[1]})")
            
            # Test essential Python modules
            essential_modules = [
                'sqlite3', 'threading', 'subprocess', 'pathlib', 'dataclasses',
                'typing', 'json', 're', 'time', 'logging', 'argparse'
            ]
            
            missing_modules = []
            for module in essential_modules:
                try:
                    importlib.import_module(module)
                except ImportError:
                    missing_modules.append(module)
            
            modules_ok = len(missing_modules) == 0
            result = CompatibilityResult(
                test_name="Essential Modules",
                passed=modules_ok,
                message=f"Essential modules {'available' if modules_ok else 'missing'}",
                details={
                    'missing_modules': ', '.join(missing_modules) if missing_modules else 'none',
                    'total_checked': str(len(essential_modules))
                }
            )
            
            self.results.append(result)
            status = "✅" if modules_ok else "❌"
            print(f"{status} Essential Modules: {len(essential_modules) - len(missing_modules)}/{len(essential_modules)} available")
            
            if missing_modules:
                print(f"   Missing: {', '.join(missing_modules)}")
                
        except Exception as e:
            result = CompatibilityResult(
                test_name="Python Compatibility",
                passed=False,
                message=f"Python compatibility check failed: {e}",
                details={'error': str(e)}
            )
            self.results.append(result)
            print(f"❌ Python compatibility check failed: {e}")
    
    def _test_system_dependencies(self):
        """Test system-level dependencies."""
        print("\n🔧 Testing System Dependencies")
        print("-" * 40)
        
        # Required system commands
        required_commands = {
            'systemctl': 'systemd service management',
            'iptables': 'iptables firewall (fallback)',
            'python3': 'Python 3 interpreter',
            'pip3': 'Python package installer'
        }
        
        # Optional commands (firewall-specific)
        optional_commands = {
            'ufw': 'UFW firewall (Ubuntu/Debian)',
            'firewall-cmd': 'firewalld (RHEL/CentOS/Fedora)',
            'journalctl': 'systemd logging'
        }
        
        # Test required commands
        missing_required = []
        for command, description in required_commands.items():
            available = shutil.which(command) is not None
            status = "✅" if available else "❌"
            print(f"{status} {command}: {description}")
            
            if not available:
                missing_required.append(command)
        
        # Test optional commands
        available_optional = []
        for command, description in optional_commands.items():
            available = shutil.which(command) is not None
            status = "✅" if available else "⚠️ "
            print(f"{status} {command}: {description}")
            
            if available:
                available_optional.append(command)
        
        # Record results
        deps_ok = len(missing_required) == 0
        result = CompatibilityResult(
            test_name="System Dependencies",
            passed=deps_ok,
            message=f"System dependencies {'satisfied' if deps_ok else 'missing'}",
            details={
                'missing_required': ', '.join(missing_required) if missing_required else 'none',
                'available_optional': ', '.join(available_optional) if available_optional else 'none',
                'firewall_options': str(len([cmd for cmd in ['ufw', 'firewall-cmd', 'iptables'] if shutil.which(cmd)]))
            }
        )
        
        self.results.append(result)
        
        if missing_required:
            print(f"\n❌ Missing required commands: {', '.join(missing_required)}")
        else:
            print(f"\n✅ All required system dependencies available")
    
    def _test_firewall_compatibility(self):
        """Test firewall system compatibility."""
        print("\n🔥 Testing Firewall Compatibility")
        print("-" * 40)
        
        firewall_systems = []
        
        # Test UFW (Ubuntu/Debian)
        if shutil.which('ufw'):
            try:
                result = subprocess.run(['ufw', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version = result.stdout.strip()
                    firewall_systems.append(f"UFW ({version})")
                    print(f"✅ UFW available: {version}")
                else:
                    print(f"⚠️  UFW found but version check failed")
            except Exception as e:
                print(f"⚠️  UFW found but not accessible: {e}")
        
        # Test firewalld (RHEL/CentOS/Fedora)
        if shutil.which('firewall-cmd'):
            try:
                result = subprocess.run(['firewall-cmd', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version = result.stdout.strip()
                    firewall_systems.append(f"firewalld ({version})")
                    print(f"✅ firewalld available: {version}")
                else:
                    print(f"⚠️  firewalld found but version check failed")
            except Exception as e:
                print(f"⚠️  firewalld found but not accessible: {e}")
        
        # Test iptables (universal fallback)
        if shutil.which('iptables'):
            try:
                result = subprocess.run(['iptables', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version = result.stdout.strip()
                    firewall_systems.append(f"iptables ({version})")
                    print(f"✅ iptables available: {version}")
                else:
                    print(f"⚠️  iptables found but version check failed")
            except Exception as e:
                print(f"⚠️  iptables found but not accessible: {e}")
        
        # Evaluate compatibility
        has_firewall = len(firewall_systems) > 0
        
        result = CompatibilityResult(
            test_name="Firewall Compatibility",
            passed=has_firewall,
            message=f"Firewall systems: {', '.join(firewall_systems) if firewall_systems else 'none detected'}",
            details={
                'available_systems': ', '.join(firewall_systems),
                'system_count': str(len(firewall_systems)),
                'recommended': self._get_recommended_firewall()
            }
        )
        
        self.results.append(result)
        
        if not has_firewall:
            print("❌ No compatible firewall system detected")
        else:
            print(f"✅ {len(firewall_systems)} firewall system(s) available")
    
    def _get_recommended_firewall(self) -> str:
        """Get recommended firewall for current platform."""
        distro = self.platform_info['distribution'].lower()
        
        if distro in ['ubuntu', 'debian']:
            return 'ufw'
        elif distro in ['rhel', 'centos', 'fedora', 'rocky', 'alma']:
            return 'firewalld'
        else:
            return 'iptables'
    
    def _test_systemd_compatibility(self):
        """Test systemd integration compatibility."""
        print("\n⚙️  Testing systemd Compatibility")
        print("-" * 40)
        
        systemd_features = []
        
        # Test systemctl availability
        if shutil.which('systemctl'):
            try:
                # Test basic systemctl functionality
                result = subprocess.run(['systemctl', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version_line = result.stdout.split('\n')[0]
                    systemd_features.append(f"systemctl ({version_line})")
                    print(f"✅ systemctl available: {version_line}")
                    
                    # Test if we can query service status (non-privileged)
                    result = subprocess.run(['systemctl', 'is-enabled', 'sshd'], 
                                          capture_output=True, text=True, timeout=5)
                    # Don't care about the result, just that command works
                    systemd_features.append("service queries work")
                    print("✅ Service status queries functional")
                    
            except Exception as e:
                print(f"⚠️  systemctl found but not fully functional: {e}")
        
        # Test journalctl availability
        if shutil.which('journalctl'):
            try:
                result = subprocess.run(['journalctl', '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    systemd_features.append("journalctl available")
                    print("✅ journalctl available for log monitoring")
            except Exception as e:
                print(f"⚠️  journalctl found but not accessible: {e}")
        
        # Check systemd directories
        systemd_dirs = [
            '/lib/systemd/system',
            '/etc/systemd/system',
            '/run/systemd/system'
        ]
        
        available_dirs = []
        for directory in systemd_dirs:
            if os.path.exists(directory):
                available_dirs.append(directory)
                print(f"✅ systemd directory: {directory}")
        
        systemd_ok = len(systemd_features) > 0 and len(available_dirs) > 0
        
        result = CompatibilityResult(
            test_name="systemd Compatibility",
            passed=systemd_ok,
            message=f"systemd {'compatible' if systemd_ok else 'not available'}",
            details={
                'features': ', '.join(systemd_features),
                'directories': ', '.join(available_dirs),
                'service_support': str(shutil.which('systemctl') is not None)
            }
        )
        
        self.results.append(result)
        
        if not systemd_ok:
            print("❌ systemd not properly available")
    
    def _test_file_system_compatibility(self):
        """Test file system permissions and paths."""
        print("\n📁 Testing File System Compatibility")
        print("-" * 40)
        
        # Standard Linux filesystem paths for RotaryShield
        required_paths = {
            '/etc': 'Configuration directory parent',
            '/var/lib': 'Data directory parent', 
            '/var/log': 'Log directory parent',
            '/run': 'Runtime directory parent (if exists)',
            '/lib/systemd/system': 'systemd service directory (if systemd)'
        }
        
        path_results = []
        
        for path, description in required_paths.items():
            exists = os.path.exists(path)
            if exists:
                readable = os.access(path, os.R_OK)
                writable = os.access(path, os.W_OK) if os.getuid() == 0 else False
                
                status = "✅" if exists and readable else "⚠️ "
                permission_info = []
                if readable:
                    permission_info.append("readable")
                if writable:
                    permission_info.append("writable")
                
                perm_str = f"({', '.join(permission_info)})" if permission_info else "(no access)"
                print(f"{status} {path}: {description} {perm_str}")
                
                path_results.append({
                    'path': path,
                    'exists': exists,
                    'readable': readable,
                    'writable': writable
                })
            else:
                print(f"⚠️  {path}: {description} (not found)")
                path_results.append({
                    'path': path,
                    'exists': exists,
                    'readable': False,
                    'writable': False
                })
        
        # Check if we can create test directories
        test_locations = ['/tmp/rotaryshield_test']
        create_success = []
        
        for location in test_locations:
            try:
                os.makedirs(location, exist_ok=True)
                if os.path.exists(location):
                    create_success.append(location)
                    os.rmdir(location)  # Clean up
                    print(f"✅ Can create directories in {os.path.dirname(location)}")
            except Exception as e:
                print(f"⚠️  Cannot create test directory {location}: {e}")
        
        fs_ok = len([p for p in path_results if p['exists']]) >= 3
        
        result = CompatibilityResult(
            test_name="File System Compatibility",
            passed=fs_ok,
            message=f"File system {'compatible' if fs_ok else 'limited access'}",
            details={
                'accessible_paths': str(len([p for p in path_results if p['exists']])),
                'total_paths': str(len(path_results)),
                'can_create_dirs': str(len(create_success) > 0)
            }
        )
        
        self.results.append(result)
    
    def _test_network_capabilities(self):
        """Test network and firewall capabilities."""
        print("\n🌐 Testing Network Capabilities")
        print("-" * 40)
        
        network_tests = []
        
        # Test if we can read network interfaces
        try:
            if os.path.exists('/proc/net/dev'):
                with open('/proc/net/dev', 'r') as f:
                    interfaces = f.read()
                    interface_count = len([l for l in interfaces.split('\n') if ':' in l]) - 1
                    network_tests.append(f"Network interfaces readable ({interface_count} found)")
                    print(f"✅ Network interfaces: {interface_count} detected")
            else:
                print("⚠️  /proc/net/dev not available")
        except Exception as e:
            print(f"⚠️  Cannot read network interfaces: {e}")
        
        # Test basic network connectivity (optional)
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', '8.8.8.8'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                network_tests.append("Internet connectivity available")
                print("✅ Internet connectivity test passed")
            else:
                print("⚠️  Internet connectivity test failed (may be expected)")
        except Exception:
            print("⚠️  Cannot test internet connectivity")
        
        # Test CAP_NET_ADMIN capability (for firewall management)
        try:
            # This is a basic test - in reality we'd need to check capabilities more thoroughly
            if os.getuid() == 0:
                network_tests.append("Running as root (firewall access likely)")
                print("✅ Running as root - firewall management possible")
            else:
                print("⚠️  Not running as root - firewall management will require sudo")
        except Exception:
            pass
        
        network_ok = len(network_tests) > 0
        
        result = CompatibilityResult(
            test_name="Network Capabilities",
            passed=network_ok,
            message=f"Network capabilities {'available' if network_ok else 'limited'}",
            details={
                'tests_passed': ', '.join(network_tests),
                'root_access': str(os.getuid() == 0)
            }
        )
        
        self.results.append(result)
    
    def _test_rotaryshield_imports(self):
        """Test RotaryShield module imports."""
        print("\n🛡️  Testing RotaryShield Module Imports")
        print("-" * 40)
        
        # Add src directory to path
        src_path = Path(__file__).parent / 'src'
        if src_path.exists():
            sys.path.insert(0, str(src_path))
        
        # Core RotaryShield modules to test
        test_modules = [
            'rotaryshield.monitoring.pattern_matcher',
            'rotaryshield.utils.validators',
            'rotaryshield.firewall.manager',
            'rotaryshield.database.ip_manager',
            'rotaryshield.config'
        ]
        
        import_results = []
        failed_imports = []
        
        for module_name in test_modules:
            try:
                module = importlib.import_module(module_name)
                import_results.append(module_name)
                print(f"✅ {module_name}")
            except ImportError as e:
                failed_imports.append((module_name, str(e)))
                print(f"❌ {module_name}: {e}")
            except Exception as e:
                failed_imports.append((module_name, f"Error: {e}"))
                print(f"⚠️  {module_name}: {e}")
        
        imports_ok = len(failed_imports) == 0
        
        result = CompatibilityResult(
            test_name="RotaryShield Imports",
            passed=imports_ok,
            message=f"Module imports {'successful' if imports_ok else 'failed'}",
            details={
                'successful_imports': str(len(import_results)),
                'failed_imports': str(len(failed_imports)),
                'total_modules': str(len(test_modules))
            }
        )
        
        self.results.append(result)
        
        if failed_imports:
            print(f"\n❌ Failed to import {len(failed_imports)} modules")
            for module, error in failed_imports:
                print(f"   {module}: {error}")
    
    def _generate_compatibility_report(self) -> bool:
        """Generate final compatibility report."""
        print("\n" + "=" * 60)
        print("📋 PLATFORM COMPATIBILITY REPORT")
        print("=" * 60)
        
        # Summary table
        print(f"{'Test Name':<25} {'Status':<8} {'Details'}")
        print("-" * 60)
        
        passed_count = 0
        for result in self.results:
            status = "✅ PASS" if result.passed else "❌ FAIL"
            if result.passed:
                passed_count += 1
            print(f"{result.test_name:<25} {status:<8} {result.message}")
        
        # Overall compatibility assessment
        total_tests = len(self.results)
        pass_rate = (passed_count / total_tests) * 100 if total_tests > 0 else 0
        
        print(f"\n📊 Compatibility Summary:")
        print(f"Tests passed: {passed_count}/{total_tests} ({pass_rate:.1f}%)")
        print(f"Platform: {self.platform_info['distribution']} {self.platform_info['version']}")
        print(f"Python: {self.platform_info['python_version']}")
        
        # Determine overall compatibility
        critical_tests = [
            "Python Version", "Essential Modules", "System Dependencies", 
            "RotaryShield Imports"
        ]
        
        critical_passed = all(
            result.passed for result in self.results 
            if result.test_name in critical_tests
        )
        
        overall_compatible = critical_passed and pass_rate >= 80
        
        print(f"\n🎯 Overall Compatibility: {'✅ COMPATIBLE' if overall_compatible else '❌ INCOMPATIBLE'}")
        
        if overall_compatible:
            print("🚀 RotaryShield should run successfully on this platform!")
        else:
            print("⚠️  This platform may have compatibility issues.")
            print("   Review failed tests above and install missing dependencies.")
        
        # Platform-specific recommendations
        self._print_platform_recommendations()
        
        return overall_compatible
    
    def _print_platform_recommendations(self):
        """Print platform-specific installation recommendations."""
        print(f"\n💡 Platform-Specific Recommendations:")
        print("-" * 40)
        
        distro = self.platform_info['distribution'].lower()
        
        if distro in ['ubuntu', 'debian']:
            print("📦 Ubuntu/Debian installation commands:")
            print("   sudo apt update")
            print("   sudo apt install python3 python3-pip ufw systemd")
            print("   sudo systemctl enable ufw")
            
        elif distro in ['rhel', 'centos', 'fedora', 'rocky', 'alma']:
            print("📦 RHEL/CentOS/Fedora installation commands:")
            print("   sudo yum install python3 python3-pip firewalld systemd")
            print("   # or: sudo dnf install python3 python3-pip firewalld systemd")
            print("   sudo systemctl enable firewalld")
            
        else:
            print("📦 Generic Linux installation requirements:")
            print("   - Python 3.8+ with pip")
            print("   - systemd for service management")
            print("   - iptables, ufw, or firewalld for firewall management")
            print("   - Standard Linux filesystem hierarchy")
        
        print("\n🔧 RotaryShield installation:")
        print("   sudo ./install.sh")


def main():
    """Run platform compatibility tests."""
    try:
        tester = PlatformCompatibilityTester()
        compatible = tester.run_all_tests()
        return 0 if compatible else 1
        
    except KeyboardInterrupt:
        print("\n🛑 Compatibility test interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Compatibility test failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())