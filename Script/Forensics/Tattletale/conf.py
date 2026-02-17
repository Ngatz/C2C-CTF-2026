with open('whatisthis.baboi', 'r') as f:
    content = f.read()

result = bytearray()
for line in content.strip().split('\n'):
    parts = line.split()
    for val in parts[1:]:          # skip alamat di kolom pertama
        word = int(val, 8)         # parse sebagai octal
        result.append(word & 0xFF)         # byte rendah (little-endian)
        result.append((word >> 8) & 0xFF)  # byte tinggi

print(result.decode('utf-8'))

