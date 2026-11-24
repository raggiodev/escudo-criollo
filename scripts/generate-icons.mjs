import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ICON_DIR = path.resolve(__dirname, '..', 'public', 'icon');
const DOCS_DIR = path.resolve(__dirname, '..', 'docs');
const OUTPUT_DIR = path.resolve(__dirname, '..', '.output');

const SIZES = [16, 32, 48, 96, 128];
const EDGE_LOGO_SIZE = 300;

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

// Brand & Argentine emblem palette RGB
const GOLD_LIGHT = [253, 230, 138]; // #FDE68A
const GOLD_MID = [245, 158, 11]; // #F59E0B
const GOLD_DARK = [217, 119, 6]; // #D97706

const INDIGO = [79, 70, 229]; // #4F46E5
const VIOLET = [124, 58, 237]; // #7C3AED
const BLUE = [37, 99, 235]; // #2563EB
const CANVAS = [13, 11, 24]; // #0D0B18

const CELESTE = [56, 189, 248]; // #38BDF8
const WHITE_FLAG = [248, 250, 252]; // #F8FAFC
const MATE_TOP = [49, 46, 129]; // #312E81
const MATE_DEEP = [20, 17, 52]; // #141134

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

  if (nx < 0) {
    return [
      Math.min(255, base[0] + 18),
      Math.min(255, base[1] + 16),
      Math.min(255, base[2] + 22),
    ];
  }
  return base;
}

/**
 * Rasterizes the v0.2.0 Emblem:
 * Outer Gold Rim -> Raggiodev Violet-Blue Shield -> Dark Core with Argentine Flag (Celeste/White/Celeste + Sun of May)
 * -> Foreground Argentine Mate Gourd + Gold Virola Rim + Angled Golden Bombilla.
 */
function sampleSubpixel(nx, ny, size) {
  const isTiny = size <= 16;
  const goldScale = 0.96;
  const violetScale = isTiny ? 0.84 : 0.86;
  const coreScale = isTiny ? 0.72 : 0.75;

  const inOuter = insideShield(nx, ny, goldScale);
  if (!inOuter) {
    if (insideShield(nx, ny - 0.04, goldScale * 1.01)) {
      return [13, 11, 24, 95];
    }
    return [0, 0, 0, 0];
  }

  // 1. FOREGROUND: Argentine Mate Gourd + Virola + Bombilla (inside core shield)
  if (insideShield(nx, ny, coreScale)) {
    // Mate gourd geometry centered at (0, 0.16)
    const mateCx = 0.0;
    const mateCy = 0.17;
    const mateRx = isTiny ? 0.34 : 0.32;
    const mateRy = isTiny ? 0.28 : 0.265;
    const dxMate = (nx - mateCx) / mateRx;
    const dyMate = (ny - mateCy) / mateRy;
    const mateDist = Math.hypot(dxMate, dyMate);

    // Virola top opening ellipse at ny = -0.05
    const virolaCy = -0.05;
    const virolaRx = isTiny ? 0.27 : 0.255;
    const virolaRy = isTiny ? 0.08 : 0.072;
    const virolaDist = Math.hypot(nx / virolaRx, (ny - virolaCy) / virolaRy);

    // Base foot trapezoid at bottom of mate (ny in [0.39, 0.48])
    const inMateFoot =
      ny >= 0.38 &&
      ny <= 0.485 &&
      Math.abs(nx) <= lerp(0.14, 0.21, (ny - 0.38) / 0.105);

    // Bombillastraw rising from center-right (0.04, -0.02) to top-right (0.35, -0.48)
    const bombillaThickness = isTiny ? 0.075 : 0.058;
    const bombillaDist = distToSegment(nx, ny, 0.04, -0.02, 0.34, -0.47);
    const mouthpieceDist = distToSegment(nx, ny, 0.28, -0.38, 0.36, -0.49);

    // Check Virola metallic rim
    if (virolaDist <= 1.08) {
      if (virolaDist >= 0.62) {
        return [...GOLD_LIGHT, 255];
      }
      // Inside mate mouth (yerba/dark interior) unless bombilla passes through
      if (bombillaDist <= bombillaThickness) {
        const gold = sampleGoldGradient(nx * 1.5, ny * 1.5);
        return [...gold, 255];
      }
      return [24, 21, 56, 255];
    }

    // Check Bombilla above the mate rim
    if (
      ny < virolaCy + 0.03 &&
      (bombillaDist <= bombillaThickness ||
        mouthpieceDist <= bombillaThickness * 1.2)
    ) {
      const gold =
        mouthpieceDist <= bombillaThickness * 1.2
          ? GOLD_LIGHT
          : sampleGoldGradient(nx * 1.4, ny * 1.4);
      return [gold[0], gold[1], gold[2], 255];
    }

    // Check Mate calabash body (truncated above virolaCy)
    if (ny >= virolaCy && mateDist <= 1.0) {
      const gold = sampleGoldGradient(nx, ny);
      // Outer golden border of mate gourd
      if (mateDist >= (isTiny ? 0.8 : 0.84)) {
        return [gold[0], gold[1], gold[2], 255];
      }
      // Decorative horizontal gold band across middle of mate
      if (Math.abs(ny - 0.17) <= (isTiny ? 0.045 : 0.035)) {
        return [GOLD_LIGHT[0], GOLD_LIGHT[1], GOLD_LIGHT[2], 255];
      }
      // Rich indigo-wood shaded gourd body
      const shade = clamp01((nx + 0.35) / 0.7);
      const bodyColor = lerpColor(MATE_TOP, MATE_DEEP, shade);
      return [bodyColor[0], bodyColor[1], bodyColor[2], 255];
    }

    if (inMateFoot) {
      const gold = sampleGoldGradient(nx, ny);
      return [gold[0], gold[1], gold[2], 255];
    }

    // 2. BACKGROUND CREST INSIDE CORE: Argentine Flag Bands (upper shield area)
    if (ny >= -0.62 && ny < -0.41) {
      return [CELESTE[0], CELESTE[1], CELESTE[2], 255];
    }
    if (ny >= -0.41 && ny < -0.22) {
      // Sun of May at center of white stripe (0, -0.315)
      const sunDist = Math.hypot(nx, ny - -0.315);
      if (sunDist <= (isTiny ? 0.11 : 0.095)) {
        return [GOLD_MID[0], GOLD_MID[1], GOLD_MID[2], 255];
      }
      return [WHITE_FLAG[0], WHITE_FLAG[1], WHITE_FLAG[2], 255];
    }
    if (ny >= -0.22 && ny < -0.02) {
      return [CELESTE[0], CELESTE[1], CELESTE[2], 255];
    }

    // Lower dark core canvas around mate
    return [CANVAS[0], CANVAS[1], CANVAS[2], 255];
  }

  // Violet-Blue heraldic inner shield band
  if (insideShield(nx, ny, violetScale)) {
    const violet = sampleVioletBlueGradient(nx, ny);
    return [violet[0], violet[1], violet[2], 255];
  }

  // Outer metallic gold shield rim
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

const cliArgs = new Set(process.argv.slice(2));
const isEdgeLogoOnly = cliArgs.has('--edge-logo') || cliArgs.has('--edge-only');

if (isEdgeLogoOnly) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  const edgeBuffer = generateIcon(EDGE_LOGO_SIZE);
  const edgeOutPath = path.join(OUTPUT_DIR, 'edge-logo-300.png');
  fs.writeFileSync(edgeOutPath, edgeBuffer);
  console.log(
    `[Escudo Criollo v0.2.0] Logo Microsoft Edge Add-ons generado: .output/edge-logo-300.png (${EDGE_LOGO_SIZE}x${EDGE_LOGO_SIZE}px, ${edgeBuffer.length} bytes)`,
  );
} else {
  fs.mkdirSync(ICON_DIR, { recursive: true });
  fs.mkdirSync(DOCS_DIR, { recursive: true });

  for (const size of SIZES) {
    const pngBuffer = generateIcon(size);
    const outPath = path.join(ICON_DIR, `${size}.png`);
    fs.writeFileSync(outPath, pngBuffer);
    console.log(
      `[Escudo Criollo v0.2.0] Icono Mate+Bandera generado: public/icon/${size}.png (${size}x${size}px, ${pngBuffer.length} bytes)`,
    );
    if (size === 128) {
      const faviconPath = path.join(DOCS_DIR, 'favicon.png');
      fs.writeFileSync(faviconPath, pngBuffer);
      console.log(
        `[Escudo Criollo v0.2.0] Favicon web actualizado: docs/favicon.png (${pngBuffer.length} bytes)`,
      );
    }
  }
}
