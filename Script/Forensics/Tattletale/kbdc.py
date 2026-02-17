import struct

# Linux input event: struct input_event { struct timeval time; __u16 type; __u16 code; __s32 value; }
# QQHHi = tv_sec(8) + tv_usec(8) + type(2) + code(2) + value(4) = 24 bytes
EVENT_SIZE = struct.calcsize('QQHHi')
print(f"Event size: {EVENT_SIZE}")

# Key code to character mapping (US keyboard)
KEY_MAP = {
    1: 'ESC', 2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    12: '-', 13: '=', 14: 'BACKSPACE', 15: 'TAB', 
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
    26: '[', 27: ']', 28: 'ENTER', 29: 'LCTRL',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l',
    39: ';', 40: "'", 41: '`', 42: 'LSHIFT', 43: '\\',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
    51: ',', 52: '.', 53: '/', 54: 'RSHIFT', 55: '*',
    56: 'LALT', 57: ' ', 58: 'CAPSLOCK',
    100: 'RALT', 102: 'HOME', 103: 'UP', 104: 'PGUP', 105: 'LEFT', 106: 'RIGHT', 
    107: 'END', 108: 'DOWN', 109: 'PGDN', 110: 'INSERT', 111: 'DELETE',
    125: 'SUPER',
}

SHIFT_MAP = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
    '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|', ';': ':', "'": '"', '`': '~',
    ',': '<', '.': '>', '/': '?', ' ': ' ',
}

with open('cron.aseng', 'rb') as f:
    data = f.read()

print(f"File size: {len(data)} bytes")
print(f"Number of events: {len(data) // EVENT_SIZE}")

shift_pressed = False
caps_lock = False
typed_chars = []
key_events = []

for i in range(0, len(data), EVENT_SIZE):
    if i + EVENT_SIZE > len(data):
        break
    tv_sec, tv_usec, ev_type, ev_code, ev_value = struct.unpack('QQHHi', data[i:i+EVENT_SIZE])
    
    # EV_KEY = 1, value 1 = press, value 0 = release, value 2 = repeat
    if ev_type == 1:
        key_name = KEY_MAP.get(ev_code, f'KEY_{ev_code}')
        
        if ev_value == 1:  # Key press
            key_events.append((tv_sec, key_name, 'press'))
            
            if key_name == 'LSHIFT' or key_name == 'RSHIFT':
                shift_pressed = True
            elif key_name == 'CAPSLOCK':
                caps_lock = not caps_lock
            elif key_name == 'BACKSPACE':
                if typed_chars:
                    typed_chars.pop()
            elif key_name == 'ENTER':
                typed_chars.append('\n')
            elif key_name == ' ':
                typed_chars.append(' ')
            elif len(key_name) == 1:
                if shift_pressed:
                    if key_name in SHIFT_MAP:
                        typed_chars.append(SHIFT_MAP[key_name])
                    else:
                        typed_chars.append(key_name.upper())
                elif caps_lock:
                    typed_chars.append(key_name.upper())
                else:
                    typed_chars.append(key_name)
        elif ev_value == 0:  # Key release
            if key_name == 'LSHIFT' or key_name == 'RSHIFT':
                shift_pressed = False

typed_text = ''.join(typed_chars)
print(f"\n=== Typed Text ===")
print(typed_text)
print(f"\n=== Raw Key Events (press only) ===")
for ts, key, action in key_events[:100]:
    print(f"  [{ts}] {key}")

