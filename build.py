#!/usr/bin/env python3
import subprocess
import sys
import platform
import os

def check_system_dependencies():
    # Only check on Linux systems
    if platform.system() != "Linux":
        return True
    
    # Check for libkrb5-dev or krb5-devel
    pkg_manager = None
    required_pkg = None
    
    # Detect package manager
    if subprocess.call(['which', 'apt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        pkg_manager = 'apt'
        required_pkg = 'libkrb5-dev'
    elif subprocess.call(['which', 'yum'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
        pkg_manager = 'yum'
        required_pkg = 'krb5-devel'
    
    if pkg_manager and required_pkg:
        # Check if package is installed
        if pkg_manager == 'apt':
            check_cmd = ['dpkg', '-s', required_pkg]
        else:  # yum
            check_cmd = ['rpm', '-q', required_pkg]
        
        if subprocess.call(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            print(f"\n\033[91mERROR: Required system package '{required_pkg}' is not installed.\033[0m")
            print(f"\nTo install the required package, run:")
            if pkg_manager == 'apt':
                print(f"    sudo apt update && sudo apt install -y {required_pkg}")
            else:  # yum
                print(f"    sudo yum check-update && sudo yum install -y {required_pkg}")
            print("\nThen run the installation again.\n")
            return False
    
    return True

def build(setup_kwargs):
    """
    This function is called by Poetry during the build process.
    It checks for system dependencies before proceeding with the build.
    """
    if not check_system_dependencies():
        sys.exit(1)
    
    # No modifications to setup_kwargs needed
    return setup_kwargs

if __name__ == "__main__":
    # This allows the script to be run directly for testing
    check_system_dependencies() 