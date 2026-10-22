import os
import zlib
import struct
import math

def save_png(width, height, pixel_fn, output_path):
    """
    Generate a valid 32-bit RGBA PNG file using only Python stdlib (struct + zlib).
    pixel_fn(x, y, width, height) -> (r, g, b, a)
    """
    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)  # Filter byte 0 (None) for each scanline
        for x in range(width):
            r, g, b, a = pixel_fn(x, y, width, height)
            raw_rows.extend([
                max(0, min(255, int(r))),
                max(0, min(255, int(g))),
                max(0, min(255, int(b))),
                max(0, min(255, int(a)))
            ])

    def make_chunk(chunk_type, data):
        c = chunk_type + data
        crc = struct.pack('>I', zlib.crc32(c) & 0xffffffff)
        return struct.pack('>I', len(data)) + c + crc

    header = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    ihdr = make_chunk(b'IHDR', ihdr_data)
    idat = make_chunk(b'IDAT', zlib.compress(bytes(raw_rows), 9))
    iend = make_chunk(b'IEND', b'')

    with open(output_path, 'wb') as f:
        f.write(header + ihdr + idat + iend)

def render_surl_icon(x, y, w, h):
    # Normalized coords from -1 to 1
    nx = (x + 0.5) / w * 2.0 - 1.0
    ny = (y + 0.5) / h * 2.0 - 1.0
    
    # Distance from center
    dist = math.sqrt(nx * nx + ny * ny)

    # Base rounded rectangle / shield boundary
    # Soft box bound
    box_r = 0.88
    ax = abs(nx)
    ay = abs(ny)
    corner = math.sqrt(max(0, ax - 0.6)**2 + max(0, ay - 0.6)**2)

    # Outside icon border
    if corner > 0.32:
        return (0, 0, 0, 0)

    # Background gradient: dark midnight navy to deep purple/black
    t = (ny + 1.0) / 2.0
    bg_r = 15 * (1 - t) + 2 * t
    bg_g = 23 * (1 - t) + 6 * t
    bg_b = 42 * (1 - t) + 23 * t

    # Outer border
    if corner > 0.28:
        return (30, 41, 59, 255)

    # Gradient for shield / lock: Cyan (#06b6d4) -> Violet (#8b5cf6) -> Magenta (#ec4899)
    grad_t = (nx + ny + 2.0) / 4.0
    s_r = int(6 * (1 - grad_t) + 168 * grad_t)
    s_g = int(182 * (1 - grad_t) + 85 * grad_t)
    s_b = int(212 * (1 - grad_t) + 247 * grad_t)

    # Shield contour
    # Top edge: ny = -0.7, coming down to points at (-0.6, -0.4), (0.6, -0.4)
    # Bottom tip at (0, 0.75)
    # Check if point is inside shield shape
    shield_w = 0.55 * (1.0 - max(0.0, (ny - 0.1) / 0.7))
    is_shield_body = (ny >= -0.5 and ny <= 0.75 and ax <= shield_w)
    is_shield_top = (ny >= -0.65 and ny < -0.5 and ax <= 0.55 * (1.0 - (abs(ny + 0.65) * 0.4)))
    in_shield = is_shield_body or is_shield_top

    # Shield edge outline
    inner_shield_w = 0.42 * (1.0 - max(0.0, (ny - 0.1) / 0.65))
    in_inner_shield = (ny >= -0.4 and ny <= 0.6 and ax <= inner_shield_w)

    # Padlock arch: center (0, -0.15), radius ~0.22, thickness ~0.08
    arch_dist = math.sqrt(nx*nx + (ny + 0.12)**2)
    in_arch = (arch_dist <= 0.22 and arch_dist >= 0.13 and ny <= -0.12)

    # Padlock body: rect from [-0.25, 0.25] horizontally, [ -0.12, 0.28 ] vertically
    in_body = (ax <= 0.26 and ny >= -0.12 and ny <= 0.28)

    # Keyhole
    in_keyhole_circle = (math.sqrt(nx*nx + (ny - 0.04)**2) <= 0.06)
    in_keyhole_slot = (ax <= 0.03 and ny >= 0.04 and ny <= 0.16)
    in_keyhole = in_keyhole_circle or in_keyhole_slot

    if in_keyhole:
        return (10, 15, 30, 255)

    if in_arch:
        return (56, 189, 248, 255)

    if in_body:
        return (s_r, s_g, s_b, 255)

    if in_shield and not in_inner_shield:
        return (s_r, s_g, s_b, 255)

    # Cyber radar ring arc
    if abs(dist - 0.72) < 0.04 and (x % 3 != 0):
        return (71, 85, 105, 180)

    return (int(bg_r), int(bg_g), int(bg_b), 255)

def main():
    icons_dir = os.path.join(os.path.dirname(__file__), 'icons')
    os.makedirs(icons_dir, exist_ok=True)

    sizes = [16, 32, 48, 128]
    for size in sizes:
        target = os.path.join(icons_dir, f'icon{size}.png')
        save_png(size, size, render_surl_icon, target)
        print(f"Generated {target} ({size}x{size})")

if __name__ == '__main__':
    main()
