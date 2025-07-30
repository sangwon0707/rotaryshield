#!/usr/bin/env python3
"""
RotaryShield Setup Script
Production-ready setup configuration with security focus.
"""

import os
import sys
from pathlib import Path
from setuptools import setup, find_packages

# Ensure we're using Python 3.8+
if sys.version_info < (3, 8):
    sys.exit('RotaryShield requires Python 3.8 or higher.')

# Get the directory containing this file
HERE = Path(__file__).parent.resolve()

# Read the README file
README_PATH = HERE / "README.md"
if README_PATH.exists():
    with open(README_PATH, encoding="utf-8") as f:
        long_description = f.read()
else:
    long_description = "RotaryShield - 3-Layer Security System for Linux servers"

# Read requirements from requirements.txt
REQUIREMENTS_PATH = HERE / "requirements.txt"
requirements = []
if REQUIREMENTS_PATH.exists():
    with open(REQUIREMENTS_PATH, encoding="utf-8") as f:
        requirements = [
            line.strip() for line in f 
            if line.strip() and not line.startswith('#') and not line.startswith('-r')
        ]

# Read version from package
version = "0.1.0"
try:
    version_file = HERE / "src" / "rotaryshield" / "__init__.py"
    with open(version_file, encoding="utf-8") as f:
        for line in f:
            if line.startswith("__version__"):
                version = line.split("=")[1].strip().strip('"').strip("'")
                break
except FileNotFoundError:
    pass

# Package configuration
setup(
    name="rotaryshield",
    version=version,
    description="3-Layer Security System: Detection, Throttling, and Blocking",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="RotaryShield Team",
    author_email="security@rotaryshield.org",
    url="https://github.com/your-org/rotaryshield",
    project_urls={
        "Bug Reports": "https://github.com/your-org/rotaryshield/issues",
        "Source": "https://github.com/your-org/rotaryshield",
        "Documentation": "https://rotaryshield.readthedocs.io/",
        "Security": "https://github.com/your-org/rotaryshield/security/policy",
    },
    
    # Package discovery
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    
    # Dependencies
    python_requires=">=3.8",
    install_requires=requirements,
    
    # Optional dependencies for enhanced functionality
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "security": [
            "bandit>=1.7.5",
            "safety>=2.3.0",
        ],
        "monitoring": [
            "prometheus_client>=0.16.0",
        ],
        "systemd": [
            "systemd-python>=235; sys_platform=='linux'",
        ],
    },
    
    # Entry points for command-line scripts
    entry_points={
        "console_scripts": [
            "rotaryshield=rotaryshield.main:main",
            "rotaryshield-config=rotaryshield.cli:config_main",
            "rotaryshield-status=rotaryshield.cli:status_main",
            "rotaryshield-control=rotaryshield.cli:control_main",
            # Phase 2 CLI Tools - Complete Suite
            "rotaryshield-monitor=rotaryshield.cli.monitor:main",
            "rotaryshield-list-blocked=rotaryshield.cli.list_blocked:main",
            "rotaryshield-unblock=rotaryshield.cli.unblock:main",
            "rotaryshield-stats=rotaryshield.cli.stats:main",
            "rotaryshield-dashboard=rotaryshield.cli.dashboard:main",
        ],
    },
    
    # Data files
    data_files=[
        # Configuration examples
        ("share/rotaryshield/configs", [
            "configs/config.example.yml",
        ]) if os.path.exists("configs/config.example.yml") else ("share/rotaryshield/configs", []),
        
        # Systemd service file
        ("lib/systemd/system", [
            "systemd/rotaryshield.service",
        ]) if os.path.exists("systemd/rotaryshield.service") else ("lib/systemd/system", []),
    ],
    
    # Include additional files from MANIFEST.in
    include_package_data=True,
    zip_safe=False,  # Required for proper systemd integration
    
    # Classification
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: No Input/Output (Daemon)",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: System :: Systems Administration",
    ],
    
    # Keywords for PyPI search
    keywords="security firewall intrusion-detection fail2ban iptables ufw systemd",
    
    # Security and license
    license="MIT",
    platforms=["Linux"],
    
    # Minimum Python version check
    cmdclass={},
)

# Post-installation security notes
if __name__ == "__main__":
    print("\n" + "="*60)
    print("RotaryShield Installation Notes")
    print("="*60)
    print("\nSecurity Recommendations:")
    print("1. Create dedicated user: sudo useradd -r -s /bin/false rotaryshield")
    print("2. Set proper permissions: sudo chown -R rotaryshield:rotaryshield /var/lib/rotaryshield")
    print("3. Configure firewall rules with least privilege")
    print("4. Review configuration file: /etc/rotaryshield/config.yml")
    print("5. Enable systemd service: sudo systemctl enable rotaryshield")
    print("\nFor complete installation guide, visit:")
    print("https://rotaryshield.readthedocs.io/en/latest/installation.html")
    print("\n" + "="*60)