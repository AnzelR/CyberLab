#!/usr/bin/env python3

import os
import subprocess
import re
import pwd
import grp

def check_root_privileges():
    return os.geteuid() == 0

def check_root_accounts():
    try:
        uid0_users = []
        with open('/etc/passwd', 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.strip().split(':')
                if parts[2] == '0':
                    uid0_users.append(parts[0])
        
        if len(uid0_users) > 1:
            return (False, f"Multiple UID 0 users found: {', '.join(uid0_users)}")
        return (True, "Only root has UID 0")
    except Exception as e:
        return (False, f"Error checking root accounts: {str(e)}")

def check_ssh_config():
    try:
        config_path = '/etc/ssh/sshd_config'
        required = {
            'PermitRootLogin': 'no',
            'Protocol': '2',
            'PasswordAuthentication': 'no',
            'PermitEmptyPasswords': 'no',
            'X11Forwarding': 'no',
            'ClientAliveInterval': '300',
            'ClientAliveCountMax': '0'
        }
        found = {}
        
        with open(config_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                key_value = re.split(r'\s+', line, 1)
                if len(key_value) < 2:
                    continue
                key = key_value[0]
                value = key_value[1].split('#')[0].strip()
                found[key] = value.lower()
        
        issues = []
        for k, v in required.items():
            current = found.get(k, '')
            if not current or current != v:
                issues.append(f"{k} should be '{v}' (found '{current}')")
        
        if issues:
            return (False, "SSH issues: " + "; ".join(issues))
        return (True, "SSH configuration is secure")
    except Exception as e:
        return (False, f"Error checking SSH config: {str(e)}")

def check_password_policies():
    try:
        issues = []
        
        # Check login.defs
        defs_path = '/etc/login.defs'
        defs_requirements = {
            'PASS_MAX_DAYS': 90,
            'PASS_MIN_DAYS': 7,
            'PASS_WARN_AGE': 7
        }
        
        with open(defs_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                key_value = re.split(r'\s+', line, 1)
                if len(key_value) < 2:
                    continue
                key = key_value[0]
                value = key_value[1].split('#')[0].strip()
                if key in defs_requirements:
                    try:
                        if int(value) > defs_requirements[key]:
                            issues.append(f"{key} should be <= {defs_requirements[key]} (current: {value})")
                    except ValueError:
                        pass
        
        # Check PAM configuration
        pam_path = '/etc/pam.d/common-password'
        pwquality_params = {
            'minlen': 14,
            'dcredit': -1,
            'ucredit': -1,
            'ocredit': -1,
            'lcredit': -1
        }
        
        if os.path.exists(pam_path):
            with open(pam_path, 'r') as f:
                pwquality_lines = [line.strip() for line in f if 'pam_pwquality.so' in line]
            
            if not pwquality_lines:
                issues.append("pam_pwquality.so not configured")
            else:
                for line in pwquality_lines:
                    if line.startswith('#'):
                        continue
                    params = dict(re.findall(r'(\w+)=(-?\d+)', line))
                    for param, req_val in pwquality_params.items():
                        curr_val = params.get(param, 0)
                        try:
                            if int(curr_val) < req_val:
                                issues.append(f"PAM {param} should be >= {req_val} (current: {curr_val})")
                        except ValueError:
                            pass
        
        if issues:
            return (False, "Password policy issues: " + "; ".join(issues))
        return (True, "Password policies are compliant")
    except Exception as e:
        return (False, f"Error checking password policies: {str(e)}")

def check_firewall():
    try:
        # Check UFW
        ufw_status = subprocess.run(['ufw', 'status'], stdout=subprocess.PIPE, text=True)
        if 'Status: active' in ufw_status.stdout:
            return (True, "UFW firewall is active")
        
        # Check iptables
        iptables = subprocess.run(['iptables', '-L', '-n'], stdout=subprocess.PIPE, text=True)
        if 'Chain INPUT (policy DROP)' not in iptables.stdout:
            return (False, "No active firewall detected or default policy not DROP")
        return (True, "IPTables is configured")
    except FileNotFoundError:
        return (False, "Firewall utilities not found")
    except Exception as e:
        return (False, f"Error checking firewall: {str(e)}")

def check_file_permissions():
    critical_files = [
        ('/etc/passwd', 0o644, 'root', 'root'),
        ('/etc/shadow', 0o640, 'root', 'shadow'),
        ('/etc/group', 0o644, 'root', 'root'),
        ('/etc/gshadow', 0o640, 'root', 'shadow'),
        ('/etc/ssh/sshd_config', 0o600, 'root', 'root'),
    ]
    
    issues = []
    for path, mode, owner, group in critical_files:
        try:
            stat = os.stat(path)
            
            # Check permissions
            if (stat.st_mode & 0o777) != mode:
                issues.append(f"{path} permissions should be {oct(mode)} (current: {oct(stat.st_mode & 0o777)})")
            
            # Check ownership
            file_owner = pwd.getpwuid(stat.st_uid).pw_name
            file_group = grp.getgrgid(stat.st_gid).gr_name
            
            if file_owner != owner:
                issues.append(f"{path} owner should be {owner} (current: {file_owner})")
            if file_group != group:
                issues.append(f"{path} group should be {group} (current: {file_group})")
                
        except Exception as e:
            issues.append(f"Error checking {path}: {str(e)}")
    
    if issues:
        return (False, "File permission issues: " + "; ".join(issues))
    return (True, "Critical file permissions are secure")

def generate_report(checks):
    print("\n🔒 Linux Security Audit Report")
    print("=" * 50)
    
    passed = 0
    for name, status, message in checks:
        status_str = "✅ PASS" if status else "❌ FAIL"
        print(f"\n{status_str} - {name}")
        print(f"   {message}")
        if status:
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"Summary: {passed}/{len(checks)} checks passed")
    print("Recommendations:")
    print("- Address all FAILED items immediately")
    print("- Regularly update system and review configurations")
    print("- Implement additional security controls as needed")

def main():
    if not check_root_privileges():
        print("⚠️  Warning: Run with root privileges for accurate results")
    
    checks = [
        ("Root Account Check", *check_root_accounts()),
        ("SSH Hardening", *check_ssh_config()),
        ("Password Policies", *check_password_policies()),
        ("Firewall Status", *check_firewall()),
        ("File Permissions", *check_file_permissions()),
    ]
    
    generate_report(checks)

if __name__ == "__main__":
    main()
