#!/usr/bin/env python3
"""Test that legitimate infrastructure/DevOps commands are NOT blocked by the PreToolUse hook.

This tests for false positives — commands that should be allowed but might
trigger the hook incorrectly.
"""

import json
import subprocess
import os
import sys

HOOK = '/home/terrabot/autoclaude/hooks/block-secrets.py'
HOME = os.path.expanduser('~')
results = {'pass': 0, 'fail': 0, 'failures': []}


def test_hook(tool_name, tool_input, expect_blocked, label):
    data = json.dumps({'tool_name': tool_name, 'tool_input': tool_input})
    result = subprocess.run(
        ['python3', HOOK], input=data, capture_output=True, text=True
    )
    blocked = result.returncode == 2
    status = 'PASS' if blocked == expect_blocked else 'FAIL'
    results['pass' if status == 'PASS' else 'fail'] += 1
    detail = result.stderr.strip()[:120] if blocked else 'allowed'
    print(f'  {status}: {label} -> {detail}')
    if status == 'FAIL':
        results['failures'].append({
            'label': label,
            'tool_name': tool_name,
            'tool_input': tool_input,
            'expect_blocked': expect_blocked,
            'actual_blocked': blocked,
            'stderr': result.stderr.strip(),
            'returncode': result.returncode,
        })


def bash(command, expect_blocked=False, label=None):
    """Shorthand for testing a Bash tool call."""
    test_hook('Bash', {'command': command}, expect_blocked, label or command)


# =============================================================================
# ANSIBLE
# =============================================================================
print("\n=== Ansible ===")
bash('ansible-playbook playbooks/deploy.yml', label='ansible-playbook basic')
bash('ansible-playbook playbooks/deploy.yml --check --diff', label='ansible-playbook --check --diff')
bash('ansible-playbook playbooks/deploy.yml -e "env=prod"', label='ansible-playbook -e env=prod')
bash('ansible-playbook playbooks/deploy.yml --limit webservers', label='ansible-playbook --limit')
bash('ansible all -m ping', label='ansible ping')
bash('ansible all -m shell -a "uptime"', label='ansible shell uptime')
bash('ansible-vault view secrets.yml --vault-password-file ~/.ansible-vault-password',
     expect_blocked=True,
     label='ansible-vault with vault-password-file (correctly blocked)')
bash('ansible-playbook playbooks/deploy.yml --vault-password-file ~/.ansible-vault-password',
     expect_blocked=True,
     label='ansible-playbook with vault-password-file (correctly blocked)')
# This is a detection gap (sensitive file accessed but not caught), not a false positive.
# A separate issue could track adding ansible-vault awareness to the hook.
bash('ansible-galaxy install geerlingguy.docker', label='ansible-galaxy install')
bash('ansible-inventory --list', label='ansible-inventory --list')
bash('ansible-lint playbooks/deploy.yml', label='ansible-lint')

# =============================================================================
# SSH OPERATIONS (no sensitive file access)
# =============================================================================
print("\n=== SSH Operations ===")
bash('ssh user@192.168.86.100 uptime', label='ssh uptime')
bash('ssh -p 2222 user@192.168.86.62 nvidia-smi', label='ssh nvidia-smi')
bash('ssh user@host systemctl status nginx', label='ssh systemctl status')
bash('ssh user@host journalctl -u docker --since "1 hour ago"', label='ssh journalctl')
bash('ssh user@host df -h', label='ssh df -h')
bash('ssh user@host free -m', label='ssh free -m')
bash('ssh-keygen -t ed25519 -C "test@example.com"', label='ssh-keygen')
bash('ssh-copy-id user@host', label='ssh-copy-id')
bash('ssh-keyscan 192.168.86.100', label='ssh-keyscan')
bash('scp /tmp/config.txt user@host:/tmp/', label='scp upload non-sensitive')
bash('scp user@host:/var/log/syslog /tmp/', label='scp download from remote')
bash('rsync -avz /tmp/files/ user@host:/tmp/backup/', label='rsync non-sensitive')

# =============================================================================
# VAULT CLI
# =============================================================================
print("\n=== Vault CLI ===")
bash('vault status', label='vault status')
bash('vault kv list secret/', label='vault kv list')
bash('vault kv get secret/database', label='vault kv get')
bash('vault kv put secret/test value=hello', label='vault kv put')
bash('vault token lookup', label='vault token lookup')
bash('vault token renew', label='vault token renew')
bash('vault secrets list', label='vault secrets list')
bash('vault audit list', label='vault audit list')
bash('vault policy list', label='vault policy list')
bash('vault policy read default', label='vault policy read')
bash('VAULT_ADDR=http://192.168.86.130:8200 vault status', label='vault status with VAULT_ADDR')

# =============================================================================
# DOCKER / CONTAINER OPERATIONS
# =============================================================================
print("\n=== Docker / Container Operations ===")
bash('docker ps', label='docker ps')
bash('docker ps -a', label='docker ps -a')
bash('docker logs mycontainer --tail 100', label='docker logs')
bash('docker exec mycontainer ls /tmp', label='docker exec ls')
bash('docker exec -it mycontainer bash', label='docker exec bash')
bash('docker images', label='docker images')
bash('docker build -t myapp .', label='docker build')
bash('docker-compose up -d', label='docker-compose up')
bash('docker-compose logs -f', label='docker-compose logs')
bash('docker inspect mycontainer', label='docker inspect')
bash('docker network ls', label='docker network ls')
bash('docker volume ls', label='docker volume ls')
bash('docker run --rm alpine echo hello', label='docker run echo')
bash('docker run --rm -v /tmp/data:/data alpine ls /data', label='docker run -v /tmp mount')
bash('docker system prune -f', label='docker system prune')
bash('docker pull nginx:latest', label='docker pull')
bash('docker stop mycontainer', label='docker stop')
bash('docker rm mycontainer', label='docker rm')

# =============================================================================
# SYSTEMCTL / JOURNALCTL
# =============================================================================
print("\n=== systemctl / journalctl ===")
bash('systemctl status nginx', label='systemctl status')
bash('systemctl restart docker', label='systemctl restart')
bash('systemctl list-units --type=service', label='systemctl list-units')
bash('systemctl is-active docker', label='systemctl is-active')
bash('journalctl -u nginx --since "1 hour ago"', label='journalctl nginx')
bash('journalctl -u docker -n 50', label='journalctl docker')
bash('journalctl --disk-usage', label='journalctl disk-usage')
bash('sudo systemctl daemon-reload', label='sudo systemctl daemon-reload')

# =============================================================================
# TERRAFORM
# =============================================================================
print("\n=== Terraform ===")
bash('terraform init', label='terraform init')
bash('terraform plan', label='terraform plan')
bash('terraform apply -auto-approve', label='terraform apply')
bash('terraform destroy -auto-approve', label='terraform destroy')
bash('terraform output', label='terraform output')
bash('terraform state list', label='terraform state list')
bash('terraform state show module.vm', label='terraform state show')
bash('terraform fmt', label='terraform fmt')
bash('terraform validate', label='terraform validate')
bash('terraform workspace list', label='terraform workspace list')
bash('terraform import aws_instance.web i-12345', label='terraform import')

# =============================================================================
# PROXMOX / KVM
# =============================================================================
print("\n=== Proxmox / KVM ===")
bash('qm list', label='qm list')
bash('qm status 100', label='qm status')
bash('qm start 100', label='qm start')
bash('qm stop 100', label='qm stop')
bash('qm config 100', label='qm config')
bash('pvesh get /nodes', label='pvesh get nodes')
bash('pct list', label='pct list')
bash('ssh user@192.168.86.101 qm list', label='ssh proxmox qm list')
bash('ssh user@192.168.86.101 pvesh get /cluster/resources', label='ssh proxmox pvesh')

# =============================================================================
# NETWORK / MONITORING
# =============================================================================
print("\n=== Network / Monitoring ===")
bash('curl http://192.168.86.127:3100/health', label='curl health check')
bash('curl -s http://localhost:8080/api/v2/products/ -H "Authorization: Token placeholder"',
     label='curl with Token placeholder (FALSE POSITIVE: placeholder value blocked)')
# FALSE POSITIVE: _RE_CURL_AUTH matches the header, but the auth value extraction
# does not check for known-safe dummy values (placeholder, example, etc.)
# unlike _RE_SECRET_ASSIGN which has an explicit safe-value list on line 264-268.
bash('wget -O /tmp/file.tar.gz http://example.com/release.tar.gz', label='wget download')
bash('ping -c 3 192.168.86.100', label='ping')
bash('traceroute 192.168.86.100', label='traceroute')
bash('nmap -sn 192.168.86.0/24', label='nmap ping sweep')
bash('dig example.com', label='dig')
bash('nslookup example.com', label='nslookup')
bash('netstat -tlnp', label='netstat')
bash('ss -tlnp', label='ss')
bash('ip addr show', label='ip addr')
bash('ip route show', label='ip route')

# =============================================================================
# PACKAGE MANAGEMENT
# =============================================================================
print("\n=== Package Management ===")
bash('apt list --installed', label='apt list')
bash('apt update', label='apt update')
bash('apt install -y nginx', label='apt install')
bash('pip install requests', label='pip install')
bash('pip freeze', label='pip freeze')
bash('npm install express', label='npm install')
bash('npm ls', label='npm ls')

# =============================================================================
# FILE OPERATIONS ON NON-SENSITIVE PATHS
# =============================================================================
print("\n=== File Operations (non-sensitive) ===")
bash('cat /etc/hostname', label='cat /etc/hostname')
bash('cat /var/log/syslog', label='cat /var/log/syslog')
bash('tail -f /var/log/nginx/access.log', label='tail nginx access log')
bash('head -20 /etc/apt/sources.list', label='head sources.list')
bash('grep -r "server" /etc/nginx/', label='grep in nginx config')
bash('find /var/log -name "*.log" -mtime -1', label='find logs')
bash('find /etc -name "*.conf"', label='find conf files')
bash('ls -la /etc/ssl/certs/', label='ls ssl certs dir')
bash('wc -l /var/log/syslog', label='wc -l syslog')
bash('du -sh /var/log/', label='du /var/log')
bash('df -h', label='df -h')
bash('free -m', label='free -m')
bash('top -b -n 1', label='top batch')
bash('ps aux', label='ps aux')
bash('lsof -i :8080', label='lsof port 8080')

# =============================================================================
# GIT OPERATIONS
# =============================================================================
print("\n=== Git Operations ===")
bash('git clone git@192.168.86.124:222/inspicere/laima.git', label='git clone')
bash('git fetch origin', label='git fetch')
bash('git pull', label='git pull')
bash('git push origin main', label='git push')
bash('git branch -a', label='git branch -a')
bash('git log --oneline -20', label='git log')
bash('git diff HEAD~1', label='git diff')
bash('git stash', label='git stash')
bash('git stash pop', label='git stash pop')
bash('git tag v1.0.0', label='git tag')
bash('git remote -v', label='git remote -v')
bash('git submodule update --init', label='git submodule update')

# =============================================================================
# WRITE / EDIT TO NON-SENSITIVE PATHS
# =============================================================================
print("\n=== Write / Edit (non-sensitive paths) ===")
test_hook('Write', {
    'file_path': '/tmp/nginx.conf',
    'content': 'server { listen 80; }'
}, False, 'Write /tmp/nginx.conf')

test_hook('Write', {
    'file_path': '/tmp/docker-compose.yml',
    'content': "version: '3'\nservices:\n  web:\n    image: nginx"
}, False, 'Write /tmp/docker-compose.yml')

test_hook('Write', {
    'file_path': '/tmp/ansible-playbook.yml',
    'content': "---\n- hosts: all\n  tasks:\n    - name: ping\n      ping:"
}, False, 'Write /tmp/ansible-playbook.yml')

test_hook('Write', {
    'file_path': '/tmp/terraform.tf',
    'content': 'resource "proxmox_vm" "test" { name = "test" }'
}, False, 'Write /tmp/terraform.tf')

test_hook('Write', {
    'file_path': '/tmp/Makefile',
    'content': 'build:\n\tdocker build -t app .'
}, False, 'Write /tmp/Makefile')

test_hook('Edit', {
    'file_path': '/tmp/config.ini',
    'old_string': 'port=80',
    'new_string': 'port=8080'
}, False, 'Edit /tmp/config.ini')

# =============================================================================
# READ OPERATIONS ON NON-SENSITIVE PATHS
# =============================================================================
print("\n=== Read (non-sensitive paths) ===")
test_hook('Read', {'file_path': '/etc/hostname'}, False, 'Read /etc/hostname')
test_hook('Read', {'file_path': '/tmp/output.log'}, False, 'Read /tmp/output.log')
test_hook('Read', {
    'file_path': '/home/terrabot/autoclaude/CLAUDE.md'
}, False, 'Read CLAUDE.md')
test_hook('Read', {
    'file_path': '/home/terrabot/autoclaude/hooks/block-secrets.py'
}, False, 'Read block-secrets.py')

# =============================================================================
# SUMMARY
# =============================================================================
print("\n" + "=" * 70)
print(f"RESULTS: {results['pass']} passed, {results['fail']} failed out of {results['pass'] + results['fail']} total")
print("=" * 70)

if results['failures']:
    print("\nFAILURES (false positives - legitimate commands that were incorrectly blocked):")
    print("-" * 70)
    for f in results['failures']:
        direction = "BLOCKED but should be ALLOWED" if f['actual_blocked'] else "ALLOWED but should be BLOCKED"
        print(f"\n  Label:    {f['label']}")
        print(f"  Tool:     {f['tool_name']}")
        if f['tool_name'] == 'Bash':
            print(f"  Command:  {f['tool_input'].get('command', '')}")
        else:
            print(f"  Input:    {json.dumps(f['tool_input'], indent=2)}")
        print(f"  Expected: {'blocked' if f['expect_blocked'] else 'allowed'}")
        print(f"  Actual:   {'blocked' if f['actual_blocked'] else 'allowed'} ({direction})")
        if f['stderr']:
            print(f"  Stderr:   {f['stderr']}")
    print()
else:
    print("\nAll tests passed! No false positives detected.")
    print()

sys.exit(1 if results['fail'] > 0 else 0)
