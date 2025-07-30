#!/usr/bin/env python3
"""
RotaryShield systemd Integration Validation Script
Tests systemd service configuration and integration capabilities.

This script validates:
- systemd service unit file syntax and security
- Service dependencies and requirements
- Security hardening directives
- Resource limits and constraints
- User/group configuration
- File permissions and directories
- Service startup and shutdown procedures
"""

import os
import sys
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Results of a systemd validation test."""
    test_name: str
    passed: bool
    severity: str  # 'critical', 'high', 'medium', 'low'
    message: str
    recommendations: List[str]


class SystemdIntegrationValidator:
    """Validates systemd service integration and security."""
    
    def __init__(self):
        self.results: List[ValidationResult] = []
        self.service_file = Path(__file__).parent / "systemd" / "rotaryshield.service"
        self.service_content = ""
        
    def run_all_validations(self) -> bool:
        """Run all systemd integration validations."""
        print("🔧 RotaryShield systemd Integration Validation")
        print("=" * 60)
        
        # Load service file
        if not self._load_service_file():
            return False
        
        # Run validation tests
        self._validate_service_syntax()
        self._validate_security_hardening()
        self._validate_resource_limits()
        self._validate_dependencies()
        self._validate_user_configuration()
        self._validate_file_paths()
        self._validate_service_lifecycle()
        self._validate_systemd_features()
        
        # Generate validation report
        return self._generate_validation_report()
    
    def _load_service_file(self) -> bool:
        """Load and parse the systemd service file."""
        print(f"📄 Loading service file: {self.service_file}")
        
        try:
            if not self.service_file.exists():
                self.results.append(ValidationResult(
                    test_name="Service File Existence",
                    passed=False,
                    severity="critical",
                    message="systemd service file not found",
                    recommendations=["Create systemd/rotaryshield.service file"]
                ))
                return False
            
            with open(self.service_file, 'r') as f:
                self.service_content = f.read()
            
            print(f"✅ Service file loaded ({len(self.service_content)} bytes)")
            return True
            
        except Exception as e:
            self.results.append(ValidationResult(
                test_name="Service File Loading",
                passed=False,
                severity="critical",
                message=f"Failed to load service file: {e}",
                recommendations=["Check file permissions and path"]
            ))
            return False
    
    def _validate_service_syntax(self):
        """Validate systemd service file syntax and structure."""
        print("\n🔍 Validating Service File Syntax")
        print("-" * 40)
        
        required_sections = ['Unit', 'Service', 'Install']
        found_sections = []
        
        # Check for required sections
        for section in required_sections:
            if f"[{section}]" in self.service_content:
                found_sections.append(section)
                print(f"✅ Section [{section}] found")
            else:
                print(f"❌ Section [{section}] missing")
        
        # Validate syntax
        syntax_valid = len(found_sections) == len(required_sections)
        
        # Check for required Unit directives
        unit_directives = {
            'Description': r'Description=.*',
            'After': r'After=.*',
            'Wants': r'Wants=.*'
        }
        
        missing_unit_directives = []
        for name, pattern in unit_directives.items():
            if not re.search(pattern, self.service_content):
                missing_unit_directives.append(name)
        
        # Check for required Service directives
        service_directives = {
            'Type': r'Type=.*',
            'ExecStart': r'ExecStart=.*',
            'User': r'User=.*',
            'Group': r'Group=.*'
        }
        
        missing_service_directives = []
        for name, pattern in service_directives.items():
            if not re.search(pattern, self.service_content):
                missing_service_directives.append(name)
        
        recommendations = []
        if missing_unit_directives:
            recommendations.append(f"Add missing Unit directives: {', '.join(missing_unit_directives)}")
        if missing_service_directives:
            recommendations.append(f"Add missing Service directives: {', '.join(missing_service_directives)}")
        
        overall_valid = syntax_valid and not missing_unit_directives and not missing_service_directives
        
        self.results.append(ValidationResult(
            test_name="Service File Syntax",
            passed=overall_valid,
            severity="critical" if not overall_valid else "low",
            message=f"Service syntax {'valid' if overall_valid else 'invalid'}",
            recommendations=recommendations
        ))
    
    def _validate_security_hardening(self):
        """Validate security hardening directives."""
        print("\n🛡️ Validating Security Hardening")
        print("-" * 40)
        
        # Critical security directives
        critical_security = {
            'NoNewPrivileges': 'NoNewPrivileges=true',
            'ProtectSystem': 'ProtectSystem=strict',
            'ProtectHome': 'ProtectHome=true',
            'PrivateDevices': 'PrivateDevices=true',
            'PrivateTmp': 'PrivateTmp=true'
        }
        
        # Advanced security directives
        advanced_security = {
            'ProtectKernelTunables': 'ProtectKernelTunables=true',
            'ProtectKernelModules': 'ProtectKernelModules=true',
            'ProtectKernelLogs': 'ProtectKernelLogs=true',
            'ProtectControlGroups': 'ProtectControlGroups=true',
            'SystemCallFilter': 'SystemCallFilter=@system-service',
            'RestrictRealtime': 'RestrictRealtime=true',
            'LockPersonality': 'LockPersonality=true'
        }
        
        missing_critical = []
        missing_advanced = []
        
        # Check critical security directives
        for name, directive in critical_security.items():
            if directive not in self.service_content:
                missing_critical.append(name)
                print(f"❌ Critical security: {name} missing")
            else:
                print(f"✅ Critical security: {name} configured")
        
        # Check advanced security directives
        for name, directive in advanced_security.items():
            if directive not in self.service_content:
                missing_advanced.append(name)
                print(f"⚠️  Advanced security: {name} missing")
            else:
                print(f"✅ Advanced security: {name} configured")
        
        # Validate capability restrictions
        if 'CapabilityBoundingSet=' in self.service_content:
            caps_match = re.search(r'CapabilityBoundingSet=(.+)', self.service_content)
            if caps_match:
                caps = caps_match.group(1).strip()
                print(f"✅ Capability restrictions: {caps}")
                
                # Check for minimal capabilities
                required_caps = ['CAP_NET_ADMIN', 'CAP_NET_RAW']
                for cap in required_caps:
                    if cap not in caps:
                        print(f"⚠️  Missing capability: {cap}")
        else:
            missing_critical.append("CapabilityBoundingSet")
            print("❌ No capability restrictions configured")
        
        severity = "critical" if missing_critical else ("medium" if missing_advanced else "low")
        recommendations = []
        
        if missing_critical:
            recommendations.append(f"Add critical security directives: {', '.join(missing_critical)}")
        if missing_advanced:
            recommendations.append(f"Consider adding advanced security: {', '.join(missing_advanced[:3])}")
        
        self.results.append(ValidationResult(
            test_name="Security Hardening",
            passed=len(missing_critical) == 0,
            severity=severity,
            message=f"Security: {len(critical_security) - len(missing_critical)}/{len(critical_security)} critical, "
                   f"{len(advanced_security) - len(missing_advanced)}/{len(advanced_security)} advanced",
            recommendations=recommendations
        ))
    
    def _validate_resource_limits(self):
        """Validate resource limits and constraints."""
        print("\n📊 Validating Resource Limits")
        print("-" * 40)
        
        resource_limits = {
            'MemoryMax': r'MemoryMax=(\d+[KMGT]?)',
            'MemoryHigh': r'MemoryHigh=(\d+[KMGT]?)',
            'CPUQuota': r'CPUQuota=(\d+%)',
            'TasksMax': r'TasksMax=(\d+)',
            'LimitNOFILE': r'LimitNOFILE=(\d+)',
            'LimitCORE': r'LimitCORE=(\d+)'
        }
        
        configured_limits = {}
        missing_limits = []
        
        for limit_name, pattern in resource_limits.items():
            match = re.search(pattern, self.service_content)
            if match:
                value = match.group(1)
                configured_limits[limit_name] = value
                print(f"✅ {limit_name}: {value}")
            else:
                missing_limits.append(limit_name)
                print(f"⚠️  {limit_name}: not configured")
        
        # Validate memory limits are reasonable
        memory_warnings = []
        if 'MemoryMax' in configured_limits:
            memory_max = configured_limits['MemoryMax']
            if memory_max.endswith('M'):
                memory_mb = int(memory_max[:-1])
                if memory_mb > 100:
                    memory_warnings.append(f"MemoryMax ({memory_max}) may be too high for security service")
                elif memory_mb < 32:
                    memory_warnings.append(f"MemoryMax ({memory_max}) may be too low")
        
        # Validate CPU quota
        cpu_warnings = []
        if 'CPUQuota' in configured_limits:
            cpu_quota = configured_limits['CPUQuota']
            if cpu_quota.endswith('%'):
                cpu_percent = int(cpu_quota[:-1])
                if cpu_percent > 300:
                    cpu_warnings.append(f"CPUQuota ({cpu_quota}) may be too high")
        
        recommendations = []
        if missing_limits:
            recommendations.append(f"Consider adding resource limits: {', '.join(missing_limits[:3])}")
        if memory_warnings:
            recommendations.extend(memory_warnings)
        if cpu_warnings:
            recommendations.extend(cpu_warnings)
        
        limits_ok = len(configured_limits) >= 4  # At least 4 limits configured
        
        self.results.append(ValidationResult(
            test_name="Resource Limits",
            passed=limits_ok,
            severity="medium" if not limits_ok else "low",
            message=f"Resource limits: {len(configured_limits)}/{len(resource_limits)} configured",
            recommendations=recommendations
        ))
    
    def _validate_dependencies(self):
        """Validate service dependencies and ordering."""
        print("\n🔗 Validating Service Dependencies")
        print("-" * 40)
        
        # Check After= directive
        after_match = re.search(r'After=(.+)', self.service_content)
        if after_match:
            after_deps = [dep.strip() for dep in after_match.group(1).split()]
            print(f"✅ After dependencies: {', '.join(after_deps)}")
            
            # Check for network dependency
            network_deps = ['network.target', 'network-online.target']
            has_network_dep = any(dep in after_deps for dep in network_deps)
            if not has_network_dep:
                print("⚠️  No network dependency found")
        else:
            print("❌ No After= dependencies configured")
            after_deps = []
        
        # Check Wants= directive
        wants_match = re.search(r'Wants=(.+)', self.service_content)
        if wants_match:
            wants_deps = [dep.strip() for dep in wants_match.group(1).split()]
            print(f"✅ Wants dependencies: {', '.join(wants_deps)}")
        else:
            print("⚠️  No Wants= dependencies configured")
            wants_deps = []
        
        # Check RequiresMountsFor= directive
        mounts_match = re.search(r'RequiresMountsFor=(.+)', self.service_content)
        if mounts_match:
            required_mounts = [mount.strip() for mount in mounts_match.group(1).split()]
            print(f"✅ Required mounts: {', '.join(required_mounts)}")
        else:
            print("⚠️  No required mounts configured")
            required_mounts = []
        
        recommendations = []
        if not after_deps:
            recommendations.append("Add After= dependencies (e.g., network-online.target)")
        if not wants_deps:
            recommendations.append("Consider adding Wants= dependencies")
        if not required_mounts:
            recommendations.append("Add RequiresMountsFor= for data directories")
        
        deps_ok = len(after_deps) > 0
        
        self.results.append(ValidationResult(
            test_name="Service Dependencies",
            passed=deps_ok,
            severity="medium" if not deps_ok else "low",
            message=f"Dependencies configured: After={len(after_deps)}, Wants={len(wants_deps)}",
            recommendations=recommendations
        ))
    
    def _validate_user_configuration(self):
        """Validate user and group configuration."""
        print("\n👤 Validating User Configuration")
        print("-" * 40)
        
        # Check User= directive
        user_match = re.search(r'User=(.+)', self.service_content)
        if user_match:
            user = user_match.group(1).strip()
            print(f"✅ Service user: {user}")
            
            # Validate user is not root
            if user == "root":
                print("❌ Service runs as root (security risk)")
                user_safe = False
            else:
                print(f"✅ Service runs as non-root user: {user}")
                user_safe = True
        else:
            print("❌ No User= directive configured")
            user = None
            user_safe = False
        
        # Check Group= directive
        group_match = re.search(r'Group=(.+)', self.service_content)
        if group_match:
            group = group_match.group(1).strip()
            print(f"✅ Service group: {group}")
            group_configured = True
        else:
            print("⚠️  No Group= directive configured")
            group = None
            group_configured = False
        
        # Check WorkingDirectory= directive
        workdir_match = re.search(r'WorkingDirectory=(.+)', self.service_content)
        if workdir_match:
            workdir = workdir_match.group(1).strip()
            print(f"✅ Working directory: {workdir}")
            workdir_configured = True
        else:
            print("⚠️  No WorkingDirectory= configured")
            workdir_configured = False
        
        # Check UMask= directive
        umask_match = re.search(r'UMask=(.+)', self.service_content)
        if umask_match:
            umask = umask_match.group(1).strip()
            print(f"✅ UMask: {umask}")
            
            # Validate umask is restrictive
            if umask in ['0022', '0027', '0077']:
                umask_secure = True
            else:
                print(f"⚠️  UMask {umask} may not be restrictive enough")
                umask_secure = False
        else:
            print("⚠️  No UMask configured")
            umask_secure = False
        
        recommendations = []
        if not user_safe:
            recommendations.append("Configure service to run as non-root user")
        if not group_configured:
            recommendations.append("Add Group= directive")
        if not workdir_configured:
            recommendations.append("Add WorkingDirectory= directive")
        if not umask_secure:
            recommendations.append("Add restrictive UMask (e.g., 0027)")
        
        user_config_ok = user_safe and group_configured
        
        self.results.append(ValidationResult(
            test_name="User Configuration",
            passed=user_config_ok,
            severity="high" if not user_safe else "medium",
            message=f"User config: User={user or 'missing'}, Group={group or 'missing'}",
            recommendations=recommendations
        ))
    
    def _validate_file_paths(self):
        """Validate file paths and permissions."""
        print("\n📁 Validating File Paths")
        print("-" * 40)
        
        # Extract file paths from service file
        paths = {
            'ExecStart': re.search(r'ExecStart=(.+)', self.service_content),
            'Environment config': re.search(r'Environment=ROTARYSHIELD_CONFIG=(.+)', self.service_content),
            'WorkingDirectory': re.search(r'WorkingDirectory=(.+)', self.service_content),
            'ReadWritePaths': re.search(r'ReadWritePaths=(.+)', self.service_content)
        }
        
        path_issues = []
        
        for path_type, match in paths.items():
            if match:
                path_value = match.group(1).strip()
                print(f"✅ {path_type}: {path_value}")
                
                # Validate paths are absolute
                if path_type in ['WorkingDirectory', 'Environment config']:
                    if not path_value.startswith('/'):
                        path_issues.append(f"{path_type} should be absolute path")
            else:
                if path_type in ['ExecStart', 'WorkingDirectory']:
                    path_issues.append(f"{path_type} not configured")
                    print(f"❌ {path_type}: not configured")
                else:
                    print(f"⚠️  {path_type}: not configured")
        
        # Check ReadWritePaths for security
        rw_paths_match = re.search(r'ReadWritePaths=(.+)', self.service_content)
        if rw_paths_match:
            rw_paths = rw_paths_match.group(1).strip().split()
            print(f"✅ ReadWrite paths: {len(rw_paths)} configured")
            
            # Validate paths are restricted
            risky_paths = ['/etc', '/usr', '/bin', '/sbin']
            for path in rw_paths:
                if any(path.startswith(risky) for risky in risky_paths):
                    path_issues.append(f"ReadWrite path {path} may be too permissive")
        
        recommendations = []
        if path_issues:
            recommendations.extend(path_issues)
        
        paths_ok = len(path_issues) == 0
        
        self.results.append(ValidationResult(
            test_name="File Paths",
            passed=paths_ok,
            severity="medium" if path_issues else "low",
            message=f"Path validation: {'passed' if paths_ok else f'{len(path_issues)} issues found'}",
            recommendations=recommendations
        ))
    
    def _validate_service_lifecycle(self):
        """Validate service lifecycle configuration."""
        print("\n🔄 Validating Service Lifecycle")
        print("-" * 40)
        
        lifecycle_directives = {
            'Type': r'Type=(.+)',
            'ExecStart': r'ExecStart=(.+)',
            'ExecStop': r'ExecStop=(.+)',
            'ExecReload': r'ExecReload=(.+)',
            'Restart': r'Restart=(.+)',
            'RestartSec': r'RestartSec=(.+)',
            'TimeoutStartSec': r'TimeoutStartSec=(.+)',
            'TimeoutStopSec': r'TimeoutStopSec=(.+)',
            'KillMode': r'KillMode=(.+)',
            'KillSignal': r'KillSignal=(.+)'
        }
        
        configured_lifecycle = {}
        missing_lifecycle = []
        
        for directive, pattern in lifecycle_directives.items():
            match = re.search(pattern, self.service_content)
            if match:
                value = match.group(1).strip()
                configured_lifecycle[directive] = value
                print(f"✅ {directive}: {value}")
            else:
                missing_lifecycle.append(directive)
                print(f"⚠️  {directive}: not configured")
        
        # Validate service type
        service_type_ok = True
        if 'Type' in configured_lifecycle:
            service_type = configured_lifecycle['Type']
            if service_type not in ['simple', 'notify', 'forking', 'oneshot']:
                service_type_ok = False
                print(f"⚠️  Service type '{service_type}' may not be appropriate")
        
        # Validate restart policy
        restart_ok = True
        if 'Restart' in configured_lifecycle:
            restart_policy = configured_lifecycle['Restart']
            if restart_policy not in ['always', 'on-failure', 'on-abnormal']:
                restart_ok = False
                print(f"⚠️  Restart policy '{restart_policy}' may not be appropriate")
        
        essential_directives = ['Type', 'ExecStart', 'Restart']
        missing_essential = [d for d in essential_directives if d in missing_lifecycle]
        
        recommendations = []
        if missing_essential:
            recommendations.append(f"Add essential lifecycle directives: {', '.join(missing_essential)}")
        if not service_type_ok:
            recommendations.append("Use appropriate service Type (simple/notify/forking)")
        if not restart_ok:
            recommendations.append("Configure appropriate Restart policy")
        
        lifecycle_ok = len(missing_essential) == 0 and service_type_ok and restart_ok
        
        self.results.append(ValidationResult(
            test_name="Service Lifecycle",
            passed=lifecycle_ok,
            severity="high" if missing_essential else "medium",
            message=f"Lifecycle: {len(configured_lifecycle)}/{len(lifecycle_directives)} configured",
            recommendations=recommendations
        ))
    
    def _validate_systemd_features(self):
        """Validate systemd-specific features and best practices."""
        print("\n⚙️  Validating systemd Features")
        print("-" * 40)
        
        # Check for systemd notification support
        if 'Type=notify' in self.service_content:
            print("✅ systemd notification support enabled")
            notify_support = True
        else:
            print("⚠️  systemd notification support not enabled")
            notify_support = False
        
        # Check for environment variables
        env_vars = re.findall(r'Environment=(.+)', self.service_content)
        if env_vars:
            print(f"✅ Environment variables: {len(env_vars)} configured")
            for env_var in env_vars:
                print(f"   {env_var}")
        else:
            print("⚠️  No environment variables configured")
        
        # Check for install section
        install_section = '[Install]' in self.service_content
        if install_section:
            print("✅ Install section present")
            
            # Check WantedBy
            wanted_by_match = re.search(r'WantedBy=(.+)', self.service_content)
            if wanted_by_match:
                wanted_by = wanted_by_match.group(1).strip()
                print(f"✅ WantedBy: {wanted_by}")
            else:
                print("⚠️  No WantedBy directive")
        else:
            print("❌ Install section missing")
        
        # Check for documentation
        documentation = re.search(r'Documentation=(.+)', self.service_content)
        if documentation:
            doc_url = documentation.group(1).strip()
            print(f"✅ Documentation: {doc_url}")
        else:
            print("⚠️  No documentation URL configured")
        
        recommendations = []
        if not notify_support:
            recommendations.append("Consider using Type=notify for better systemd integration")
        if not env_vars:
            recommendations.append("Add environment variables for configuration")
        if not install_section:
            recommendations.append("Add [Install] section with WantedBy directive")
        
        features_ok = install_section
        
        self.results.append(ValidationResult(
            test_name="systemd Features",
            passed=features_ok,
            severity="medium" if not features_ok else "low",
            message=f"systemd features: {'properly configured' if features_ok else 'missing critical features'}",
            recommendations=recommendations
        ))
    
    def _generate_validation_report(self) -> bool:
        """Generate comprehensive validation report."""
        print("\n" + "=" * 60)
        print("📋 SYSTEMD INTEGRATION VALIDATION REPORT")
        print("=" * 60)
        
        # Summary table
        print(f"{'Test Name':<25} {'Status':<8} {'Severity':<10} {'Issues'}")
        print("-" * 70)
        
        passed_count = 0
        critical_failed = 0
        high_failed = 0
        
        for result in self.results:
            status = "✅ PASS" if result.passed else "❌ FAIL"
            if result.passed:
                passed_count += 1
            else:
                if result.severity == "critical":
                    critical_failed += 1
                elif result.severity == "high":
                    high_failed += 1
            
            print(f"{result.test_name:<25} {status:<8} {result.severity.upper():<10} {result.message}")
        
        # Overall assessment
        total_tests = len(self.results)
        pass_rate = (passed_count / total_tests) * 100 if total_tests > 0 else 0
        
        print(f"\n📊 Validation Summary:")
        print(f"Tests passed: {passed_count}/{total_tests} ({pass_rate:.1f}%)")
        print(f"Critical failures: {critical_failed}")
        print(f"High severity failures: {high_failed}")
        
        # Determine overall status
        if critical_failed > 0:
            overall_status = "❌ CRITICAL ISSUES"
            ready_for_production = False
        elif high_failed > 0:
            overall_status = "⚠️  HIGH PRIORITY ISSUES"
            ready_for_production = False
        elif pass_rate < 80:
            overall_status = "⚠️  NEEDS IMPROVEMENT"
            ready_for_production = False
        else:
            overall_status = "✅ PRODUCTION READY"
            ready_for_production = True
        
        print(f"\n🎯 Overall Status: {overall_status}")
        
        if ready_for_production:
            print("🚀 systemd service is ready for production deployment!")
        else:
            print("⚠️  Service requires fixes before production deployment.")
        
        # Recommendations
        all_recommendations = []
        for result in self.results:
            if not result.passed and result.recommendations:
                all_recommendations.extend(result.recommendations)
        
        if all_recommendations:
            print(f"\n💡 Priority Recommendations:")
            print("-" * 40)
            for i, rec in enumerate(all_recommendations[:10], 1):  # Top 10 recommendations
                print(f"{i:2d}. {rec}")
            
            if len(all_recommendations) > 10:
                print(f"    ... and {len(all_recommendations) - 10} more recommendations")
        
        # systemd commands for testing
        print(f"\n🔧 Manual Testing Commands:")
        print("-" * 40)
        print("# Validate service file syntax:")
        print("sudo systemd-analyze verify systemd/rotaryshield.service")
        print("\n# Test service installation:")
        print("sudo cp systemd/rotaryshield.service /etc/systemd/system/")
        print("sudo systemctl daemon-reload")
        print("sudo systemctl enable rotaryshield")
        print("\n# Check service status:")
        print("sudo systemctl status rotaryshield")
        print("sudo systemctl show rotaryshield")
        
        return ready_for_production


def main():
    """Run systemd integration validation."""
    try:
        validator = SystemdIntegrationValidator()
        production_ready = validator.run_all_validations()
        return 0 if production_ready else 1
        
    except KeyboardInterrupt:
        print("\n🛑 Validation interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())