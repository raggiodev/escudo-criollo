import {
  AuditFinding,
  EcommerceContext,
  MAX_SCANNED_TEXT_CHARS,
  MAX_URL_LENGTH,
  RiskLevel,
  StoreAuditReport,
  parseSafeHttpUrl,
  safeTruncate,
} from '../../types';
import {
  extractBoundedSemanticText,
  getSafeAttr,
  getSafeDocumentUrl,
  isAnchorElement,
  isHtmlElement,
} from '../../utils/dom-safety';
import {
  extractCUITsFromText,
  inspectDataFiscalDOM,
} from '../v01-cuit-arca/validator';

const WHITELISTED_OFFICIAL_DOMAINS = [
  'mercadolibre.com.ar',
  'mercadopago.com.ar',
  'mercadolibre.com',
  'afip.gob.ar',
  'arca.gob.ar',
  'bcra.gob.ar',
  'argentina.gob.ar',
  'anses.gob.ar',
  'nic.ar',
  'bna.com.ar',
  'galicia.ar',
  'bancogalicia.com.ar',
  'santander.com.ar',
  'bbva.com.ar',
  'macro.com.ar',
  'icbc.com.ar',
  'bancoprovincia.com.ar',
  'bancociudad.com.ar',
  'brubank.com',
  'uala.com.ar',
  'naranjax.com',
] as const;

const FREE_SUBDOMAIN_SUFFIXES = [
  '.mitiendanube.com',
  '.lojavirtualnuvem.com.br',
  '.myshopify.com',
  '.empretienda.com.ar',
  '.wixsite.com',
] as const;

const FOOTER_SELECTORS = [
  'footer',
  '[role="contentinfo"]',
  '[class*="footer" i]',
  '[id*="footer" i]',
  '[class*="pie-pagina" i]',
] as const;

const STORE_CONTENT_SELECTORS = [
  'header',
  '[class*="header" i]',
  '[class*="topbar" i]',
  '[class*="announcement" i]',
  '[class*="banner" i]',
  '[class*="promo" i]',
  '[class*="discount" i]',
  '[class*="payment" i]',
  '[class*="checkout" i]',
  '[class*="product" i]',
  '[class*="cart" i]',
  'main',
  '[role="main"]',
] as const;

// Linear-time O(n) heuristics regexes
const CART_ACTION_REGEX =
  /\b(?:agregar\s+al\s+carrito|a[ñn]adir\s+al\s+carrito|comprar\s+ahora|finalizar\s+compra|iniciar\s+compra|ir\s+al\s+carrito|mi\s+carrito)\b/i;

const ARS_PRICE_REGEX =
  /(?:\$\s?\d{1,3}(?:[.,]\d{3})+(?:[.,]\d{2})?)|(?:\bARS\s?\d{3,})/i;

const AGGRESSIVE_TRANSFER_SCAM_REGEX =
  /(?:\b(?:25|[3-8]\d)\s*%\s*(?:de\s+)?(?:off|descuento|dto|ahorro)\b[^\n.]{0,50}\btransferencia\b)|(?:\btransferencia\b[^\n.]{0,50}\b(?:25|[3-8]\d)\s*%\s*(?:de\s+)?(?:off|descuento|dto)\b)|(?:\b(?:50|60|70|80)\s*%\s*off\s+en\s+toda\s+la\s+tienda\b)|(?:\b[23]\s*x\s*1\s+en\s+tod[oa](?:s|\s+la\s+tienda)?\b)/i;

const CONTACT_PHONE_OR_WA_REGEX =
  /\b(?:whatsapp|tel[eé]fono|atenci[oó]n\s+al\s+cliente|\+?54\s*9?\s*\d{2,4}[-\s]?\d{3,4}[-\s]?\d{4})\b/i;

const PHYSICAL_ADDRESS_REGEX =
  /\b(?:av\.|avenida|calle|boulevard|bv\.|piso|local\s+\d|sucursal|domicilio|direcci[oó]n|caba|capital\s+federal|buenos\s+aires|c[oó]rdoba|rosario|mendoza|tucum[aá]n|la\s+plata|mar\s+del\s+plata)\b/i;

const RAZON_SOCIAL_REGEX =
  /\b(?:raz[oó]n\s+social|s\.?r\.?l\.?|s\.?a\.?s\.?|s\.?a\.?|sociedad\s+an[oó]nima)\b/i;

const SOCIAL_DOMAINS = [
  'instagram.com',
  'facebook.com',
  'fb.com',
  'tiktok.com',
  'wa.me',
  'api.whatsapp.com',
] as const;

function matchesDomainOrSubdomain(hostname: string, target: string): boolean {
  return hostname === target || hostname.endsWith(`.${target}`);
}

function isOfficialWhitelistedHost(hostname: string): boolean {
  if (!hostname) {
    return false;
  }
  if (
    hostname.endsWith('.gob.ar') ||
    hostname.endsWith('.gov.ar') ||
    hostname.endsWith('.mil.ar')
  ) {
    return true;
  }
  return WHITELISTED_OFFICIAL_DOMAINS.some((domain) =>
    matchesDomainOrSubdomain(hostname, domain),
  );
}

function isFreeStoreSubdomain(hostname: string): boolean {
  return FREE_SUBDOMAIN_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

/**
 * Collects bounded plaintext via TreeWalker ONLY when a page lacks semantic <main>/<footer>/<header> wrappers,
 * guaranteeing zero layout reflow (never uses innerText) and strict O(n) cap.
 */
function extractFallbackBodyText(doc: Document, maxChars: number): string {
  if (!doc.body || !isHtmlElement(doc.body, doc)) {
    return '';
  }
  const cap = Math.min(maxChars, 30_000);
  const parts: string[] = [];
  let total = 0;
  let nodesVisited = 0;

  // NodeFilter.SHOW_TEXT === 4
  const walker = doc.createTreeWalker(doc.body, 4);
  let current = walker.nextNode();
  while (current && total < cap && nodesVisited < 600) {
    nodesVisited++;
    const parentTag = current.parentElement?.tagName.toLowerCase();
    if (
      parentTag !== 'script' &&
      parentTag !== 'style' &&
      parentTag !== 'noscript' &&
      parentTag !== 'svg'
    ) {
      const val = current.nodeValue?.trim();
      if (val) {
        const slice = val.slice(0, cap - total);
        parts.push(slice);
        total += slice.length;
      }
    }
    current = walker.nextNode();
  }
  return parts.join(' ');
}

function collectDomFingerprints(doc: Document): {
  assetUrlsSample: string;
  inlineScriptSample: string;
  generatorMeta: string;
  bodyClasses: string;
  hasCartButtonsInDom: boolean;
} {
  const assetChunks: string[] = [];

  const scripts = doc.querySelectorAll('script');
  const maxScripts = Math.min(scripts.length, 80);
  const inlineChunks: string[] = [];
  let inlineLen = 0;

  for (let i = 0; i < maxScripts; i++) {
    const s = scripts[i];
    if (!isHtmlElement(s, doc)) {
      continue;
    }
    const src = s.getAttribute('src');
    if (src) {
      assetChunks.push(src.slice(0, 200));
    } else if (inlineLen < 12_000) {
      const snippet = (s.textContent ?? '').slice(0, 1500);
      if (snippet) {
        inlineChunks.push(snippet);
        inlineLen += snippet.length;
      }
    }
  }

  const links = doc.querySelectorAll('link[href]');
  const maxLinks = Math.min(links.length, 60);
  for (let i = 0; i < maxLinks; i++) {
    const l = links[i];
    if (!isHtmlElement(l, doc)) {
      continue;
    }
    const href = l.getAttribute('href');
    if (href) {
      assetChunks.push(href.slice(0, 200));
    }
  }

  let generatorMeta = '';
  const metaGen = doc.querySelector('meta[name="generator" i]');
  if (metaGen && isHtmlElement(metaGen, doc)) {
    generatorMeta = getSafeAttr(metaGen, 'content', 160).toLowerCase();
  }

  const bodyClasses =
    doc.body && isHtmlElement(doc.body, doc)
      ? getSafeAttr(doc.body, 'class', 512).toLowerCase()
      : '';

  // Check buttons/inputs for cart actions
  let hasCartButtonsInDom = false;
  const buttons = doc.querySelectorAll(
    'button, input[type="submit"], a[class*="cart" i], a[class*="buy" i], [data-store*="cart" i]',
  );
  const maxBtns = Math.min(buttons.length, 80);
  for (let i = 0; i < maxBtns; i++) {
    const b = buttons[i];
    if (!isHtmlElement(b, doc)) {
      continue;
    }
    const label = `${b.textContent ?? ''} ${b.getAttribute('value') ?? ''} ${b.getAttribute('aria-label') ?? ''}`.slice(
      0,
      160,
    );
    if (CART_ACTION_REGEX.test(label)) {
      hasCartButtonsInDom = true;
      break;
    }
  }

  return {
    assetUrlsSample: assetChunks.join(' ').toLowerCase(),
    inlineScriptSample: inlineChunks.join(' '),
    generatorMeta,
    bodyClasses,
    hasCartButtonsInDom,
  };
}

/**
 * Identifies whether the current document is an online store or shopping platform,
 * detecting Tiendanube, Shopify, WooCommerce, MercadoLibre, MercadoShops, VTEX, PrestaShop, Magento,
 * or Generic Argentine ARS Storefronts.
 */
export function detectEcommerceContext(
  doc: Document,
  urlStr: string,
): EcommerceContext {
  const parsedUrl = getSafeDocumentUrl(doc, urlStr);
  const hostname = parsedUrl ? parsedUrl.hostname.toLowerCase() : '';
  const isWhitelistedOfficial = isOfficialWhitelistedHost(hostname);
  const isFreeSubdomain = isFreeStoreSubdomain(hostname);

  if (
    matchesDomainOrSubdomain(hostname, 'mercadolibre.com.ar') ||
    matchesDomainOrSubdomain(hostname, 'mercadolibre.com')
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: true,
      platform: 'MERCADOLIBRE',
      platformLabel: 'MercadoLibre Oficial',
      isFreeSubdomain: false,
      hasArsPricing: true,
      hasCartControls: true,
    };
  }

  if (isWhitelistedOfficial) {
    return {
      isEcommerce: false,
      isWhitelistedOfficial: true,
      platform: 'SITIO_OFICIAL',
      platformLabel: 'Portal Oficial Verificado',
      isFreeSubdomain: false,
      hasArsPricing: false,
      hasCartControls: false,
    };
  }

  const fp = collectDomFingerprints(doc);
  let sampleText = extractBoundedSemanticText(
    doc,
    [...STORE_CONTENT_SELECTORS, ...FOOTER_SELECTORS],
    50_000,
  );
  if (sampleText.length < 1200) {
    sampleText = `${sampleText}\n${extractFallbackBodyText(doc, 20_000)}`;
  }

  const hasArsPricing = ARS_PRICE_REGEX.test(sampleText);
  const hasCartControls =
    fp.hasCartButtonsInDom || CART_ACTION_REGEX.test(sampleText);

  if (
    hostname.endsWith('.mercadoshops.com.ar') ||
    fp.assetUrlsSample.includes('mercadoshops.com.ar')
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'MERCADOSHOPS',
      platformLabel: 'MercadoShops',
      isFreeSubdomain,
      hasArsPricing: true,
      hasCartControls: true,
    };
  }

  if (
    hostname.endsWith('.mitiendanube.com') ||
    hostname.endsWith('.lojavirtualnuvem.com.br') ||
    fp.assetUrlsSample.includes('cdn.tiendanube.com') ||
    fp.assetUrlsSample.includes('mitiendanube.com') ||
    fp.assetUrlsSample.includes('d26lpennugtm8s.cloudfront.net') ||
    /\bLS\.store\b/.test(fp.inlineScriptSample)
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'TIENDANUBE',
      platformLabel: 'Tiendanube',
      isFreeSubdomain,
      hasArsPricing,
      hasCartControls: true,
    };
  }

  if (
    hostname.endsWith('.myshopify.com') ||
    fp.assetUrlsSample.includes('cdn.shopify.com') ||
    fp.generatorMeta.includes('shopify') ||
    /\bShopify\.shop\b/.test(fp.inlineScriptSample)
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'SHOPIFY',
      platformLabel: 'Shopify',
      isFreeSubdomain,
      hasArsPricing,
      hasCartControls: true,
    };
  }

  if (
    fp.generatorMeta.includes('woocommerce') ||
    fp.bodyClasses.includes('woocommerce') ||
    fp.bodyClasses.includes('wc-cart') ||
    fp.assetUrlsSample.includes('woocommerce') ||
    doc.querySelector('[class*="wc-cart" i], [class*="woocommerce" i]') !== null
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'WOOCOMMERCE',
      platformLabel: 'WooCommerce',
      isFreeSubdomain,
      hasArsPricing,
      hasCartControls: true,
    };
  }

  if (
    fp.assetUrlsSample.includes('vtexassets.com') ||
    fp.assetUrlsSample.includes('vteximg.com.br') ||
    fp.bodyClasses.includes('vtex') ||
    /\bvtex\b/i.test(fp.generatorMeta)
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'VTEX',
      platformLabel: 'VTEX',
      isFreeSubdomain,
      hasArsPricing,
      hasCartControls: true,
    };
  }

  if (
    fp.generatorMeta.includes('prestashop') ||
    fp.assetUrlsSample.includes('prestashop') ||
    /\bprestashop\b/i.test(fp.inlineScriptSample)
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'PRESTASHOP',
      platformLabel: 'PrestaShop',
      isFreeSubdomain,
      hasArsPricing,
      hasCartControls: true,
    };
  }

  if (
    fp.generatorMeta.includes('magento') ||
    fp.assetUrlsSample.includes('mage/cookies') ||
    doc.querySelector('[data-mage-init]') !== null
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'MAGENTO',
      platformLabel: 'Magento',
      isFreeSubdomain,
      hasArsPricing,
      hasCartControls: true,
    };
  }

  if (hasCartControls && hasArsPricing) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'TIENDA_ARGENTINA',
      platformLabel: 'Tienda Online (ARS)',
      isFreeSubdomain,
      hasArsPricing: true,
      hasCartControls: true,
    };
  }

  return {
    isEcommerce: false,
    isWhitelistedOfficial: false,
    platform: 'NO_ECOMMERCE',
    platformLabel: 'Sitio Web General',
    isFreeSubdomain,
    hasArsPricing,
    hasCartControls,
  };
}

function inspectFooterSocialLinks(
  doc: Document,
  baseUrlStr: string,
): string[] {
  const brokenSocials: string[] = [];
  const seen = new Set<HTMLAnchorElement>();

  for (const selector of FOOTER_SELECTORS) {
    let containers: NodeListOf<Element>;
    try {
      containers = doc.querySelectorAll(selector);
    } catch {
      continue;
    }

    const maxContainers = Math.min(containers.length, 15);
    for (let c = 0; c < maxContainers; c++) {
      const container = containers[c];
      if (!isHtmlElement(container, doc)) {
        continue;
      }
      const anchors = container.querySelectorAll('a');
      const maxAnchors = Math.min(anchors.length, 120);

      for (let i = 0; i < maxAnchors; i++) {
        const a = anchors[i];
        if (!isAnchorElement(a, doc) || seen.has(a)) {
          continue;
        }
        seen.add(a);

        const rawHref = (a.getAttribute('href') ?? '').trim();
        const aria = getSafeAttr(a, 'aria-label', 120);
        const title = getSafeAttr(a, 'title', 120);
        const cls = getSafeAttr(a, 'class', 120);
        const text = safeTruncate(a.textContent ?? '', 80);

        let imgHint = '';
        const childImg = a.querySelector('img');
        if (childImg && isHtmlElement(childImg, doc)) {
          imgHint = `${getSafeAttr(childImg, 'alt', 80)} ${getSafeAttr(childImg, 'src', 120)}`;
        }

        const combinedHint =
          `${rawHref} ${aria} ${title} ${cls} ${text} ${imgHint}`.toLowerCase();

        const mentionedNetwork =
          combinedHint.includes('instagram')
            ? 'Instagram'
            : combinedHint.includes('facebook') || /\bfb\b/.test(combinedHint)
              ? 'Facebook'
              : combinedHint.includes('whatsapp') || combinedHint.includes('wa.me')
                ? 'WhatsApp'
                : combinedHint.includes('tiktok')
                  ? 'TikTok'
                  : null;

        if (!mentionedNetwork) {
          continue;
        }

        // Ignore social share buttons (/sharer, intent)
        if (
          combinedHint.includes('sharer') ||
          combinedHint.includes('share')
        ) {
          continue;
        }

        if (
          rawHref === '' ||
          rawHref === '#' ||
          rawHref === '/#' ||
          rawHref.toLowerCase().startsWith('javascript:')
        ) {
          brokenSocials.push(`${mentionedNetwork} (href="${rawHref || 'vacío'}")`);
          continue;
        }

        const parsed = parseSafeHttpUrl(rawHref, baseUrlStr);
        if (!parsed) {
          brokenSocials.push(`${mentionedNetwork} (enlace inválido)`);
          continue;
        }

        const host = parsed.hostname.toLowerCase();
        const isSocialHost = SOCIAL_DOMAINS.some((d) =>
          matchesDomainOrSubdomain(host, d),
        );

        if (isSocialHost) {
          const cleanPath = parsed.pathname.replace(/\/+/g, '').trim();
          const hasWhatsappPhone =
            (host === 'api.whatsapp.com' || host.endsWith('whatsapp.com')) &&
            Boolean(parsed.searchParams.get('phone')?.trim());

          if (cleanPath.length === 0 && !hasWhatsappPhone) {
            brokenSocials.push(
              `${mentionedNetwork} (${parsed.hostname}/ sin perfil)`,
            );
          }
        }
      }
    }
  }

  return Array.from(new Set(brokenSocials)).slice(0, 4);
}

/**
 * Full security & anti-scam forensic audit combining Modulo 11 CUIT inspection,
 * ARCA/AFIP F.960 Data Fiscal DOM verification, and Argentine storefront scam heuristics.
 */
export function auditStoreSecurity(
  doc: Document,
  urlStr: string,
): StoreAuditReport {
  const parsedUrl = getSafeDocumentUrl(doc, urlStr);
  const safeUrl = parsedUrl
    ? safeTruncate(parsedUrl.href, MAX_URL_LENGTH)
    : safeTruncate(urlStr, MAX_URL_LENGTH);
  const hostname = parsedUrl ? safeTruncate(parsedUrl.hostname.toLowerCase(), 256) : 'desconocido';
  const isHttps = parsedUrl ? parsedUrl.protocol === 'https:' : false;
  const pageTitle = safeTruncate(typeof doc.title === 'string' ? doc.title : '', 256);

  const ecommerce = detectEcommerceContext(doc, safeUrl);
  const dataFiscal = inspectDataFiscalDOM(doc, safeUrl);

  // Bounded semantic text extraction (strictly <= 150,000 chars total)
  const footerText = extractBoundedSemanticText(doc, FOOTER_SELECTORS, 60_000);
  const storeBodyText = extractBoundedSemanticText(
    doc,
    STORE_CONTENT_SELECTORS,
    MAX_SCANNED_TEXT_CHARS - footerText.length,
  );
  let combinedBoundedText = `${footerText}\n${storeBodyText}`.slice(
    0,
    MAX_SCANNED_TEXT_CHARS,
  );
  if (combinedBoundedText.trim().length < 800) {
    combinedBoundedText = `${combinedBoundedText}\n${extractFallbackBodyText(doc, 30_000)}`.slice(
      0,
      MAX_SCANNED_TEXT_CHARS,
    );
  }

  const cuits = extractCUITsFromText(combinedBoundedText);
  const validCuits = cuits.filter((c) => c.isValid);
  const invalidCuits = cuits.filter((c) => !c.isValid);

  const findings: AuditFinding[] = [];

  // Short-circuit for whitelisted top-tier official domains (MercadoLibre, .gob.ar, official banks)
  if (ecommerce.isWhitelistedOfficial) {
    findings.push({
      id: 'whitelisted-official-domain',
      severity: 'SAFE',
      title: 'Dominio oficial verificado',
      detail:
        'Estás en el dominio auténtico de una plataforma líder, entidad bancaria u organismo oficial argentino.',
      evidence: hostname,
    });

    if (validCuits.length > 0) {
      findings.push({
        id: 'valid-cuit-present',
        severity: 'SAFE',
        title: 'CUIT oficial verificado (Módulo 11)',
        detail:
          'El CUIT informado cumple con la validación matemática y prefijo oficial de ARCA/AFIP.',
        evidence: validCuits
          .slice(0, 2)
          .map((c) => c.formatted)
          .join(' · '),
      });
    }

    if (dataFiscal.status === 'VERIFIED_OFFICIAL_QR') {
      findings.push({
        id: 'official-data-fiscal-qr',
        severity: 'SAFE',
        title: 'QR Data Fiscal F.960 oficial activo',
        detail:
          'El sello Data Fiscal enlaza correctamente al servidor de validación de ARCA/AFIP.',
      });
    }

    return {
      url: safeUrl,
      hostname,
      pageTitle,
      isHttps,
      timestamp: Date.now(),
      ecommerce,
      trustScore: isHttps ? 98 : 75,
      riskLevel: isHttps ? 'SAFE' : 'WARNING',
      pillHeadline:
        ecommerce.platform === 'MERCADOLIBRE'
          ? 'Tienda Verificada · Sitio Oficial'
          : 'Portal Oficial Verificado',
      cuits,
      dataFiscal,
      findings,
    };
  }

  let score = ecommerce.isEcommerce ? 70 : 75;
  let criticalRedFlagsCount = 0;

  // === CRITICAL RED FLAGS (DANGER) ===
  if (dataFiscal.status === 'FORGED_STATIC_SEAL') {
    criticalRedFlagsCount++;
    score -= 55;
    findings.push({
      id: 'forged-data-fiscal-seal',
      severity: 'DANGER',
      title: 'Sello Data Fiscal ARCA/AFIP falsificado o sin vínculo',
      detail:
        'Se detectó una imagen de Data Fiscal (F.960) pegada de forma estática o con un enlace falso que NO valida en afip.gob.ar ni arca.gob.ar. Es una maniobra típica de tiendas truchas para engañar compradores antes de pedir una transferencia.',
      evidence: dataFiscal.forgedEvidence ?? undefined,
    });
  }

  if (invalidCuits.length > 0) {
    criticalRedFlagsCount++;
    score -= 50;
    const sampleBad = invalidCuits[0];
    findings.push({
      id: 'invalid-cuit-modulo11',
      severity: 'DANGER',
      title: 'CUIT inválido o inventado en la página',
      detail:
        'El número de CUIT publicado falla la verificación matemática Módulo 11 o usa dígitos ficticios. Desconfiá de inmediato: ningún comercio legalmente inscripto tiene un CUIT inválido.',
      evidence: sampleBad
        ? `${sampleBad.formatted} — ${sampleBad.reason}`
        : undefined,
    });
  }

  const brokenSocialLinks = inspectFooterSocialLinks(
    doc,
    parsedUrl ? parsedUrl.href : 'https://localhost/',
  );
  if (brokenSocialLinks.length > 0) {
    criticalRedFlagsCount++;
    score -= 32;
    findings.push({
      id: 'broken-footer-social-links',
      severity: 'DANGER',
      title: 'Redes sociales falsas o vacías en el pie de página',
      detail:
        'Los botones de Instagram, Facebook o WhatsApp del footer están rotos, vacíos (href="#") o llevan a la portada sin usuario real. Las tiendas descartables de estafas suelen dejar íconos falsos.',
      evidence: safeTruncate(brokenSocialLinks.join(' · '), 220),
    });
  }

  const aggressivePromoMatch = AGGRESSIVE_TRANSFER_SCAM_REGEX.exec(
    combinedBoundedText,
  );
  if (ecommerce.isFreeSubdomain && aggressivePromoMatch) {
    criticalRedFlagsCount++;
    score -= 42;
    findings.push({
      id: 'free-subdomain-aggressive-transfer',
      severity: 'DANGER',
      title: 'Subdominio gratuito + descuentos agresivos por transferencia',
      detail:
        'Combina un subdominio gratuito sin dominio propio con ofertas agresivas por transferencia o 2x1 masivo. Alerta máxima de estafa en anuncios de Instagram/Facebook: las transferencias a CBU/CVU no se pueden revertir.',
      evidence: safeTruncate(aggressivePromoMatch[0], 160),
    });
  } else if (ecommerce.isEcommerce && aggressivePromoMatch && validCuits.length === 0) {
    score -= 18;
    findings.push({
      id: 'aggressive-transfer-unverified',
      severity: 'WARNING',
      title: 'Descuento agresivo por transferencia sin CUIT visible',
      detail:
        'Ofrece descuentos muy altos por transferencia bancaria pero no informa CUIT en la página. Nunca transfieras dinero sin antes verificar el CUIT del titular de la cuenta.',
      evidence: safeTruncate(aggressivePromoMatch[0], 160),
    });
  }

  // === CAUTION FLAGS (WARNING) ===
  if (
    ecommerce.isEcommerce &&
    validCuits.length === 0 &&
    invalidCuits.length === 0 &&
    dataFiscal.status === 'MISSING_DATA_FISCAL'
  ) {
    score -= 24;
    findings.push({
      id: 'missing-cuit-and-data-fiscal',
      severity: 'WARNING',
      title: 'Tienda sin CUIT ni QR Data Fiscal F.960',
      detail:
        'El comercio vende online pero no exhibe CUIT ni código QR Data Fiscal de ARCA/AFIP en el pie de página (exigido por Ley 24.240 de Defensa del Consumidor). Exigí el CUIT y verificalo en BCRA antes de transferir.',
    });
  } else if (
    ecommerce.isEcommerce &&
    validCuits.length > 0 &&
    dataFiscal.status === 'MISSING_DATA_FISCAL'
  ) {
    score -= 8;
    findings.push({
      id: 'cuit-without-qr-seal',
      severity: 'WARNING',
      title: 'CUIT presente pero sin QR Data Fiscal interactivo',
      detail:
        'Informa un CUIT matemáticamente válido, pero no incluye el sello F.960 clickeable hacia ARCA/AFIP. Comprobá que el titular del CBU/CVU coincida exactamente con este CUIT.',
    });
  }

  if (ecommerce.isEcommerce) {
    const contactScanTarget = footerText.length > 40 ? footerText : combinedBoundedText;
    const hasPhoneLink =
      doc.querySelector(
        'a[href^="tel:"], a[href*="wa.me/"], a[href*="whatsapp.com/send"]',
      ) !== null;
    const hasContact =
      hasPhoneLink || CONTACT_PHONE_OR_WA_REGEX.test(contactScanTarget);
    const hasAddress = PHYSICAL_ADDRESS_REGEX.test(contactScanTarget);
    const hasRazonSocial = RAZON_SOCIAL_REGEX.test(contactScanTarget);

    if (!hasContact && !hasAddress && !hasRazonSocial) {
      score -= 14;
      findings.push({
        id: 'missing-contact-and-address',
        severity: 'WARNING',
        title: 'Sin dirección física, teléfono ni Razón Social en el footer',
        detail:
          'No se encontró domicilio comercial, línea de contacto verificable ni Razón Social en el pie de página. Si no entregan el pedido, dificulta cualquier reclamo formal.',
      });
    }
  }

  if (ecommerce.isFreeSubdomain && !aggressivePromoMatch) {
    score -= 10;
    findings.push({
      id: 'free-unverified-subdomain',
      severity: 'WARNING',
      title: 'Subdominio gratuito sin dominio propio (.com.ar)',
      detail:
        'La tienda opera sobre un subdominio gratuito en lugar de un dominio registrado en NIC.ar. Verificá antigüedad y referencias reales antes de comprar.',
      evidence: hostname,
    });
  }

  if (!isHttps) {
    score -= 25;
    findings.push({
      id: 'insecure-http-connection',
      severity: 'WARNING',
      title: 'Conexión no segura (sin cifrado HTTPS)',
      detail:
        'Esta página transmite datos sin cifrado SSL/TLS. No ingreses tarjetas de crédito, claves ni datos personales.',
    });
  }

  // === POSITIVE TRUST SIGNALS (SAFE) ===
  if (validCuits.length > 0) {
    score += 16;
    findings.push({
      id: 'valid-modulo11-cuit',
      severity: 'SAFE',
      title: 'CUIT matemáticamente válido en el sitio',
      detail:
        'Superó el algoritmo Módulo 11 y posee prefijo oficial de ARCA/AFIP. Usá el botón "Consultar BCRA" para confirmar el nombre real de la empresa o persona antes de transferir.',
      evidence: validCuits
        .slice(0, 3)
        .map((c) => `${c.formatted} (${c.entityLabel})`)
        .join(' · '),
    });
  }

  if (dataFiscal.status === 'VERIFIED_OFFICIAL_QR') {
    score += 22;
    findings.push({
      id: 'verified-official-data-fiscal',
      severity: 'SAFE',
      title: 'QR Data Fiscal F.960 oficial de ARCA/AFIP verificado',
      detail:
        'El sello fiscal enlaza a un endpoint oficial *.afip.gob.ar / *.arca.gob.ar con código verificador activo.',
      evidence: dataFiscal.officialQrUrl
        ? safeTruncate(dataFiscal.officialQrUrl, 120)
        : undefined,
    });
  }

  const isNicArDomain =
    (hostname.endsWith('.com.ar') ||
      hostname.endsWith('.net.ar') ||
      hostname.endsWith('.org.ar') ||
      hostname.endsWith('.tur.ar') ||
      (hostname.endsWith('.ar') && !hostname.endsWith('.gob.ar'))) &&
    !ecommerce.isFreeSubdomain;

  if (isNicArDomain) {
    score += 10;
    findings.push({
      id: 'nic-ar-registered-domain',
      severity: 'SAFE',
      title: 'Dominio propio registrado en NIC Argentina (.ar)',
      detail:
        'Los dominios .com.ar / .ar requieren titularidad validada mediante Clave Fiscal ante ARCA/AFIP en NIC Argentina.',
      evidence: hostname,
    });
  }

  const trustScore = Math.max(0, Math.min(100, Math.round(score)));

  // Determine semantic RiskLevel & Steamcito-style pill headline
  let riskLevel: RiskLevel;
  let pillHeadline: string;

  if (criticalRedFlagsCount > 0 || (ecommerce.isEcommerce && trustScore < 35)) {
    riskLevel = 'DANGER';
    pillHeadline = 'Alerta: Posible Tienda Trucha';
  } else if (!ecommerce.isEcommerce) {
    if (!isHttps) {
      riskLevel = 'WARNING';
      pillHeadline = 'Precaución · Sitio sin HTTPS';
    } else {
      riskLevel = 'NEUTRAL';
      pillHeadline =
        validCuits.length > 0
          ? 'Sitio Web · CUIT OK'
          : 'Sitio Web · Sin alertas';
    }
  } else if (
    trustScore >= 75 &&
    (validCuits.length > 0 || dataFiscal.status === 'VERIFIED_OFFICIAL_QR')
  ) {
    riskLevel = 'SAFE';
    pillHeadline =
      validCuits.length > 0
        ? 'Tienda Verificada · CUIT OK'
        : 'Tienda Verificada · QR Fiscal OK';
  } else {
    riskLevel = 'WARNING';
    pillHeadline =
      dataFiscal.status === 'MISSING_DATA_FISCAL' && validCuits.length === 0
        ? 'Precaución · Sin Data Fiscal'
        : 'Precaución · Verificar Datos';
  }

  // Sort findings by urgency: DANGER -> WARNING -> SAFE
  const severityRank: Record<AuditFinding['severity'], number> = {
    DANGER: 0,
    WARNING: 1,
    SAFE: 2,
  };
  findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

  return {
    url: safeUrl,
    hostname,
    pageTitle,
    isHttps,
    timestamp: Date.now(),
    ecommerce,
    trustScore,
    riskLevel,
    pillHeadline,
    cuits,
    dataFiscal,
    findings,
  };
}

