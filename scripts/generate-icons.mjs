import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ICON_DIR = path.resolve(__dirname, '..', 'public', 'icon');

const SIZES = [16, 32, 48, 96, 128];

// Precompute IEEE 802.3 CRC32 table for valid PNG chunk checksums
const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[n] = c >>> 0;
}

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makePngChunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);

  const crcInput = Buffer.concat([typeBuf, data]);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(crcInput), 0);

  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function encodeRgbaToPng(width, height, rgba) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // 8-bit depth
  ihdr[9] = 6; // RGBA color type
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  const stride = width * 4 + 1;
  const rawScanlines = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    const rowStart = y * stride;
    rawScanlines[rowStart] = 0; // Filter type 0 (None)
    rgba.copy(rawScanlines, rowStart + 1, y * width * 4, (y + 1) * width * 4);
  }

  const compressed = zlib.deflateSync(rawScanlines, { level: 9 });

  return Buffer.concat([
    signature,
    makePngChunk('IHDR', ihdr),
    makePngChunk('IDAT', compressed),
    makePngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function clamp01(v) {
  return v < 0 ? 0 : v > 1 ? 1 : v;
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

function lerpColor(c1, c2, t) {
  const k = clamp01(t);
  return [
    lerp(c1[0], c2[0], k),
    lerp(c1[1], c2[1], k),
    lerp(c1[2], c2[2], k),
  ];
}

function distToSegment(px, py, ax, ay, bx, by) {
  const vx = bx - ax;
  const vy = by - ay;
  const wx = px - ax;
  const wy = py - ay;
  const lenSq = vx * vx + vy * vy;
  let t = lenSq > 0 ? (wx * vx + wy * vy) / lenSq : 0;
  t = clamp01(t);
  const dx = px - (ax + t * vx);
  const dy = py - (ay + t * vy);
  return Math.hypot(dx, dy);
}

/**
 * Evaluates normalized shield containment metric.
 * scale = 1.0 is outer shield boundary; smaller scale = inset shield layers.
 */
function insideShield(nx, ny, scale) {
  const x = nx / scale;
  const y = (ny - 0.02) / scale;

  const topArch = -0.84 + 0.1 * Math.pow(Math.min(1.3, Math.abs(x) / 0.78), 2);
  if (y < topArch || y > 0.88) {
    return false;
  }

  let halfWidth;
  if (y <= -0.06) {
    // Subtle shoulder rounding at the very top corners
    halfWidth = 0.78;
    if (y < -0.66) {
      const cy = -0.66;
      const cx = 0.66;
      if (Math.abs(x) > cx) {
        const dx = Math.abs(x) - cx;
        const dy = y - cy;
        if (Math.hypot(dx / 0.12, dy / 0.16) > 1.0) {
          return false;
        }
      }
    }
  } else {
    const t = (y - -0.06) / (0.88 - -0.06);
    halfWidth = 0.78 * (1 - Math.pow(t, 1.82));
  }

  return Math.abs(x) <= halfWidth;
}

// Brand palette RGB
const GOLD_LIGHT = [253, 230, 138]; // #FDE68A
const GOLD_MID = [245, 158, 11]; // #F59E0B
const GOLD_DARK = [217, 119, 6]; // #D97706

const INDIGO = [79, 70, 229]; // #4F46E5
const VIOLET = [124, 58, 237]; // #7C3AED
const BLUE = [37, 99, 235]; // #2563EB
const CANVAS = [13, 11, 24]; // #0D0B18

function sampleGoldGradient(nx, ny) {
  const diag = clamp01((nx + ny + 1.5) / 3.0);
  return diag < 0.5
    ? lerpColor(GOLD_LIGHT, GOLD_MID, diag * 2)
    : lerpColor(GOLD_MID, GOLD_DARK, (diag - 0.5) * 2);
}

function sampleVioletBlueGradient(nx, ny) {
  const diag = clamp01((nx + ny + 1.5) / 3.0);
  const base =
    diag < 0.55
      ? lerpColor(INDIGO, VIOLET, diag / 0.55)
      : lerpColor(VIOLET, BLUE, (diag - 0.55) / 0.45);

  // Subtle heraldic split sheen on left side for tactical depth
  if (nx < 0) {
    return [
      Math.min(255, base[0] + 18),
      Math.min(255, base[1] + 16),
      Math.min(255, base[2] + 22),
    ];
  }
  return base;
}

function sampleSubpixel(nx, ny, size) {
  // Boost stroke thickness slightly at 16px for crisp toolbar legibility
  const isTiny = size <= 16;
  const goldScale = 0.96;
  const darkRingScale = isTiny ? 0.79 : 0.83;
  const coreScale = isTiny ? 0.74 : 0.78;

  const inOuter = insideShield(nx, ny, goldScale);
  if (!inOuter) {
    // Subtle dark drop shadow right under the shield
    if (insideShield(nx, ny - 0.04, goldScale * 1.01)) {
      return [13, 11, 24, 95];
    }
    return [0, 0, 0, 0];
  }

  // Checkmark geometry inside core shield
  const checkThickness = isTiny ? 0.135 : 0.108;
  const d1 = distToSegment(nx, ny, -0.29, 0.03, -0.06, 0.27);
  const d2 = distToSegment(nx, ny, -0.06, 0.27, 0.34, -0.2);
  const checkDist = Math.min(d1, d2);

  // Southern Cross / Argentine Sun 4-point spark near crown (for >= 32px)
  let inStar = false;
  if (!isTiny) {
    const sx = Math.abs(nx);
    const sy = Math.abs(ny - -0.44);
    inStar = Math.pow(sx / 0.12, 0.65) + Math.pow(sy / 0.12, 0.65) <= 1.0;
  }

  if (checkDist <= checkThickness || inStar) {
    const gold = sampleGoldGradient(nx * 1.4, ny * 1.4);
    // Crisp specular highlight on top of checkmark
    const highlight = lerpColor(gold, [255, 248, 214], 0.28);
    return [highlight[0], highlight[1], highlight[2], 255];
  }

  if (insideShield(nx, ny, coreScale)) {
    // Drop shadow behind checkmark for high contrast
    const d1Shadow = distToSegment(nx, ny - 0.045, -0.29, 0.03, -0.06, 0.27);
    const d2Shadow = distToSegment(nx, ny - 0.045, -0.06, 0.27, 0.34, -0.2);
    if (Math.min(d1Shadow, d2Shadow) <= checkThickness * 1.08) {
      return [13, 11, 24, 255];
    }

    const core = sampleVioletBlueGradient(nx, ny);
    return [core[0], core[1], core[2], 255];
  }

  if (insideShield(nx, ny, darkRingScale)) {
    return [CANVAS[0], CANVAS[1], CANVAS[2], 255];
  }

  const rimGold = sampleGoldGradient(nx, ny);
  return [rimGold[0], rimGold[1], rimGold[2], 255];
}

function generateIcon(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const samples = 4; // 4x4 SSAA (16 samples/pixel)

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let rAcc = 0;
      let gAcc = 0;
      let bAcc = 0;
      let aAcc = 0;

      for (let sy = 0; sy < samples; sy++) {
        const py = y + (sy + 0.5) / samples;
        const ny = (py / size) * 2 - 1;
        for (let sx = 0; sx < samples; sx++) {
          const px = x + (sx + 0.5) / samples;
          const nx = (px / size) * 2 - 1;
          const [r, g, b, a] = sampleSubpixel(nx, ny, size);
          const alphaNorm = a / 255;
          // Premultiplied alpha accumulation prevents dark fringes at edges
          rAcc += r * alphaNorm;
          gAcc += g * alphaNorm;
          bAcc += b * alphaNorm;
          aAcc += a;
        }
      }

      const totalSamples = samples * samples;
      const outA = Math.round(aAcc / totalSamples);
      const idx = (y * size + x) * 4;

      if (outA === 0) {
        rgba[idx] = 0;
        rgba[idx + 1] = 0;
        rgba[idx + 2] = 0;
        rgba[idx + 3] = 0;
      } else {
        const alphaSumNorm = aAcc / 255;
        rgba[idx] = Math.round(Math.min(255, rAcc / alphaSumNorm));
        rgba[idx + 1] = Math.round(Math.min(255, gAcc / alphaSumNorm));
        rgba[idx + 2] = Math.round(Math.min(255, bAcc / alphaSumNorm));
        rgba[idx + 3] = outA;
      }
    }
  }

  return encodeRgbaToPng(size, size, rgba);
}

fs.mkdirSync(ICON_DIR, { recursive: true });

for (const size of SIZES) {
  const pngBuffer = generateIcon(size);
  const outPath = path.join(ICON_DIR, `${size}.png`);
  fs.writeFileSync(outPath, pngBuffer);
  console.log(`[Escudo Criollo] Icono generado: public/icon/${size}.png (${size}x${size}px, ${pngBuffer.length} bytes)`);
}

