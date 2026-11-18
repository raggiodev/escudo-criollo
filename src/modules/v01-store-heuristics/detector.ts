import {
  LEGAL_AUDIT_DISCLAIMER,
  SCORE_CAPS,
  SCORING_WEIGHTS,
} from '../../config/scoring-config';
import registriesData from '../../data/verified-registries.json';
import {
  AuditFinding,
  DataFiscalAuditResult,
  EcommerceContext,
  MAX_SCANNED_TEXT_CHARS,
  MAX_URL_LENGTH,
  RiskLevel,
  ScoreBreakdownItem,
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
  NON_ECOMMERCE_PLATFORMS,
  extractCUITsFromText,
  inspectDataFiscalDOM,
  isNonEcommercePlatformHost,
} from '../v01-cuit-arca/validator';
import {
  TyposquattingMatch,
  detectBrandTyposquatting,
  hasSuspiciousUrlUserinfo,
  matchesAnyRegisteredDomain,
  matchesRegisteredDomain,
} from './domain-matcher';

export {
  NON_ECOMMERCE_PLATFORMS,
  isNonEcommercePlatformHost,
  LEGAL_AUDIT_DISCLAIMER,
  detectBrandTyposquatting,
  matchesRegisteredDomain,
};

export const VERIFIED_CACE_EVENT_DOMAINS: readonly string[] =
  registriesData.caceOfficialEvents;

export const VERIFIED_FINANCIAL_ENTITIES: readonly string[] =
  registriesData.financialAndBrokersAr;

export const VERIFIED_MARKETPLACES: readonly string[] =
  registriesData.marketplacesAr;

export const VERIFIED_DIRECT_RETAILERS_AR: readonly string[] =
  registriesData.retailersAr;

// Unified national verified retailers export (CACE + Marketplaces + Direct Retailers)
export const VERIFIED_ARGENTINE_RETAILERS: readonly string[] = [
  ...registriesData.caceOfficialEvents,
  ...registriesData.marketplacesAr,
  ...registriesData.retailersAr,
];

export const VERIFIED_INTERNATIONAL_PLATFORMS: readonly string[] =
  registriesData.internationalPlatforms;

export const VERIFIED_OFFICIAL_INSTITUTIONS: readonly string[] =
  registriesData.officialInstitutionsAr;

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
  '[class*="carrito" i]',
  'main',
  '[role="main"]',
] as const;

// Linear-time O(n) heuristics regexes
const CART_ACTION_REGEX =
  /\b(?:agregar\s+al\s+carrito|a[ñn]adir\s+al\s+carrito|comprar\s+ahora|finalizar\s+compra|iniciar\s+compra|ir\s+al\s+carrito|mi\s+carrito)\b/i;

const ARS_PRICE_REGEX =
  /(?:\$\s*\d{1,3}(?:[.,]\d{3})+(?:[.,]\d{2})?)|(?:\bARS\s*\d{3,})/i;

const AGGRESSIVE_TRANSFER_SCAM_REGEX =
  /(?:\b(?:25|[3-8]\d)\s*%\s*(?:de\s+)?(?:off|descuento|dto|ahorro)\b[^\n.]{0,50}\btransferencia\b)|(?:\btransferencia\b[^\n.]{0,50}\b(?:25|[3-8]\d)\s*%\s*(?:de\s+)?(?:off|descuento|dto)\b)|(?:\b(?:50|60|70|80)\s*%\s*off\s+en\s+toda\s+la\s+tienda\b)|(?:\b[23]\s*x\s*1\s+en\s+tod[oa](?:s|\s+la\s+tienda)?\b)/i;

export const HAS_CONTACT_REGEX =
  /\b(?:whatsapp|tel[eé]fono|atenci[oó]n\s+al\s+cliente|bot[oó]n\s+de\s+arrepentimiento|defensa\s+de\s+las\s+y\s+los\s+consumidores|defensa\s+del\s+consumidor|\+?54\s*9?\s*\d{2,4}[-\s]?\d{3,4}[-\s]?\d{4})\b/i;

const CONTACT_PHONE_OR_WA_REGEX = HAS_CONTACT_REGEX;

const PHYSICAL_ADDRESS_REGEX =
  /\b(?:av\.|avenida|calle|boulevard|bv\.|piso|local\s+\d|sucursal|domicilio|direcci[oó]n|caba|capital\s+federal|buenos\s+aires|c[oó]rdoba|rosario|mendoza|tucum[aá]n|la\s+plata|mar\s+del\s+plata)\b/i;

export const HAS_LEGAL_ENTITY_REGEX =
  /\b(?:raz[oó]n\s+social|s\.?r\.?l\.?|s\.?a\.?s\.?|s\.?a\.?|sociedad\s+an[oó]nima|bot[oó]n\s+de\s+arrepentimiento|defensa\s+de\s+las\s+y\s+los\s+consumidores|t[eé]rminos\s+y\s+condiciones)\b/i;

const RAZON_SOCIAL_REGEX = HAS_LEGAL_ENTITY_REGEX;

const SOCIAL_DOMAINS = [
  'instagram.com',
  'facebook.com',
  'fb.com',
  'tiktok.com',
  'wa.me',
  'api.whatsapp.com',
] as const;

/**
 * Detects whether a URL belongs to any official portfolio, repository, academic profile,
 * or social channel of Escudo Criollo's creator: Raggiodev (Fernando Andres Raggio).
 */
export function isRaggiodevCreatorUrl(rawUrl: string): boolean {
  const parsed = parseSafeHttpUrl(rawUrl);
  if (!parsed) {
    return false;
  }
  const fullHost = parsed.hostname.toLowerCase();
  const baseHost = fullHost.replace(/^www\./, '');
  const pathLower = parsed.pathname.toLowerCase();

  if (pathLower.includes('demo-tienda-trucha')) {
    return false;
  }

  if (
    fullHost === 'raggiodev.com' ||
    fullHost.endsWith('.raggiodev.com') ||
    fullHost === 'raggiodev.github.io' ||
    fullHost === 'raggiodev.substack.com'
  ) {
    return true;
  }

  if (
    (baseHost === 'linktr.ee' ||
      baseHost === 'github.com' ||
      baseHost === 'x.com' ||
      baseHost === 'twitter.com') &&
    /^\/raggiodev(?:\/|$)/i.test(pathLower)
  ) {
    return true;
  }

  if (
    baseHost === 'orcid.org' &&
    /^\/0009-0000-1674-327x(?:\/|$)/i.test(pathLower)
  ) {
    return true;
  }

  if (
    baseHost === 'linkedin.com' &&
    /^\/in\/raggiodev(?:\/|$)/i.test(pathLower)
  ) {
    return true;
  }

  if (
    (baseHost === 'youtube.com' || baseHost === 'substack.com') &&
    /^\/@raggiodev(?:\/|$)/i.test(pathLower)
  ) {
    return true;
  }

  return false;
}

function isRaggiodevCreatorHq(parsedUrl: URL | null): boolean {
  if (!parsedUrl) {
    return false;
  }
  return isRaggiodevCreatorUrl(parsedUrl.href);
}

function isVerifiedCaceEventHost(hostname: string): boolean {
  return matchesAnyRegisteredDomain(hostname, VERIFIED_CACE_EVENT_DOMAINS);
}

function isVerifiedFinancialHost(hostname: string): boolean {
  return matchesAnyRegisteredDomain(hostname, VERIFIED_FINANCIAL_ENTITIES);
}

function isVerifiedMarketplaceHost(hostname: string): boolean {
  return matchesAnyRegisteredDomain(hostname, VERIFIED_MARKETPLACES);
}

function isVerifiedArgentineStoreHost(hostname: string): boolean {
  return matchesAnyRegisteredDomain(hostname, VERIFIED_DIRECT_RETAILERS_AR);
}

function isVerifiedInternationalStoreHost(hostname: string): boolean {
  return matchesAnyRegisteredDomain(hostname, VERIFIED_INTERNATIONAL_PLATFORMS);
}

function isVerifiedInstitutionalHost(hostname: string): boolean {
  if (!hostname) {
    return false;
  }
  if (
    hostname.endsWith('.gob.ar') ||
    hostname.endsWith('.gov.ar') ||
    hostname.endsWith('.mil.ar') ||
    hostname.endsWith('.edu.ar')
  ) {
    return true;
  }
  return matchesAnyRegisteredDomain(hostname, VERIFIED_OFFICIAL_INSTITUTIONS);
}

function isFreeStoreSubdomain(hostname: string): boolean {
  return FREE_SUBDOMAIN_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

function clampScoreFromBreakdown(
  items: readonly ScoreBreakdownItem[],
  maxCap: number = SCORE_CAPS.MAX_OFFICIAL_SCORE,
): number {
  const rawTotal = items.reduce((acc, item) => acc + item.delta, 0);
  return Math.max(0, Math.min(maxCap, Math.round(rawTotal)));
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
  hasCartButtonsOrIconsInDom: boolean;
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

  // Check buttons, cart icons, and checkout controls
  let hasCartButtonsOrIconsInDom =
    doc.querySelector(
      '[class*="cart" i], [class*="carrito" i], [id*="cart" i], [id*="carrito" i], [aria-label*="carrito" i], a[href*="/cart" i], a[href*="/carrito" i], a[href*="/checkout" i]',
    ) !== null;

  if (!hasCartButtonsOrIconsInDom) {
    const buttons = doc.querySelectorAll(
      'button, input[type="submit"], a[class*="buy" i], [data-store*="cart" i]',
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
        hasCartButtonsOrIconsInDom = true;
        break;
      }
    }
  }

  return {
    assetUrlsSample: assetChunks.join(' ').toLowerCase(),
    inlineScriptSample: inlineChunks.join(' '),
    generatorMeta,
    bodyClasses,
    hasCartButtonsOrIconsInDom,
  };
}

/**
 * Identifies whether the current document is an online store, marketplace, financial/broker platform,
 * or general website, using externalized verified registries and anti-typosquatting checks.
 */
export function detectEcommerceContext(
  doc: Document,
  urlStr: string,
  precomputedDataFiscal?: DataFiscalAuditResult,
  precomputedTyposquat?: TyposquattingMatch | null,
): EcommerceContext {
  const parsedUrl = getSafeDocumentUrl(doc, urlStr);
  const isFileDemoScamStore =
    parsedUrl?.protocol === 'file:' &&
    parsedUrl.pathname.toLowerCase().includes('demo-tienda-trucha');
  const hostname =
    parsedUrl && parsedUrl.hostname
      ? parsedUrl.hostname.toLowerCase()
      : isFileDemoScamStore
        ? 'urbansneakers-ar.mitiendanube.com'
        : '';
  const isFreeSubdomain = isFreeStoreSubdomain(hostname);

  // 0. Raggiodev Creator Easter Egg (all official portfolios, repositories, and social channels of Raggiodev)
  if (isRaggiodevCreatorHq(parsedUrl)) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: true,
      platform: 'RAGGIODEV_HQ',
      platformLabel: '🟢 Easter Egg encontrado',
      isFreeSubdomain: false,
      hasArsPricing: false,
      hasCartControls: false,
    };
  }

  // 0b. Phishing / Typosquatting / Userinfo Credential Spoofing
  const typosquat =
    precomputedTyposquat !== undefined
      ? precomputedTyposquat
      : detectBrandTyposquatting(hostname);
  if (hasSuspiciousUrlUserinfo(parsedUrl) || typosquat !== null) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'TIENDA_ARGENTINA',
      platformLabel: 'Dominio Imitador',
      isFreeSubdomain,
      hasArsPricing: false,
      hasCartControls: false,
    };
  }

  // 0c. Non-Ecommerce Platforms (GitHub, Google, YouTube, X, LinkedIn, News Portals, Steamcito, Impuestito, etc.)
  if (isNonEcommercePlatformHost(hostname)) {
    return {
      isEcommerce: false,
      isWhitelistedOfficial: false,
      platform: 'NO_ECOMMERCE',
      platformLabel: 'Sitio Web General',
      isFreeSubdomain: false,
      hasArsPricing: false,
      hasCartControls: false,
    };
  }

  // 1. Official CACE Event Portals (CyberMonday, Hot Sale, CACE)
  if (isVerifiedCaceEventHost(hostname)) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: true,
      platform: 'COMERCIO_OFICIAL_AR',
      platformLabel: 'Evento Oficial CACE',
      isFreeSubdomain: false,
      hasArsPricing: true,
      hasCartControls: true,
    };
  }

  // 2. Regulated Financial Entities, Banks & Brokers (ALyCs / CNV / BCRA — e.g. InvertirOnline, Galicia, BNA)
  if (isVerifiedFinancialHost(hostname)) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: true,
      platform: 'ENTIDAD_FINANCIERA',
      platformLabel: 'Entidad Financiera Oficial',
      isFreeSubdomain: false,
      hasArsPricing: true,
      hasCartControls: false,
    };
  }

  // 3. Official Marketplaces where Third-Party Sellers Operate (MercadoLibre, Shopee AR, Frávega, etc.)
  if (isVerifiedMarketplaceHost(hostname)) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: true,
      platform: 'MARKETPLACE_OFICIAL',
      platformLabel: 'Marketplace Oficial',
      isFreeSubdomain: false,
      hasArsPricing: true,
      hasCartControls: true,
    };
  }

  // 4. Verified National Direct Argentine Retailers (CompraGamer, Cetrogar, Easy, Farmacity, etc.)
  if (isVerifiedArgentineStoreHost(hostname)) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: true,
      platform: 'COMERCIO_OFICIAL_AR',
      platformLabel: 'Comercio Oficial AR',
      isFreeSubdomain: false,
      hasArsPricing: true,
      hasCartControls: true,
    };
  }

  // 5. Verified International & Cross-Border Courier Platforms (Amazon, Tiendamia, Steam, etc.)
  if (isVerifiedInternationalStoreHost(hostname)) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: true,
      platform: 'ECOMMERCE_INTERNACIONAL',
      platformLabel: 'E-Commerce Internacional',
      isFreeSubdomain: false,
      hasArsPricing: false,
      hasCartControls: true,
    };
  }

  // 6. Verified Government (.gob.ar) & Universities (.edu.ar / palermo.edu / uba.ar)
  if (isVerifiedInstitutionalHost(hostname)) {
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
    fp.hasCartButtonsOrIconsInDom || CART_ACTION_REGEX.test(sampleText);

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

  const dataFiscal =
    precomputedDataFiscal ??
    inspectDataFiscalDOM(doc, parsedUrl ? parsedUrl.href : urlStr);

  // Unknown domain: require actual cart/buy controls (or a forged tax seal) to classify as an e-commerce store.
  // Merely having '$' numbers in text without cart controls classifies as NO_ECOMMERCE.
  if (
    (hasCartControls &&
      (hasArsPricing || dataFiscal.status === 'VERIFIED_OFFICIAL_QR')) ||
    dataFiscal.status === 'FORGED_STATIC_SEAL'
  ) {
    return {
      isEcommerce: true,
      isWhitelistedOfficial: false,
      platform: 'TIENDA_ARGENTINA',
      platformLabel: 'Tienda Online (ARS)',
      isFreeSubdomain,
      hasArsPricing,
      hasCartControls,
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
          matchesRegisteredDomain(host, d),
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
 * ARCA/AFIP F.960 Data Fiscal DOM & SPA hydration verification, national/international/financial
 * verified registries, anti-typosquatting checks, and transparent scoreBreakdown accounting.
 */
export function auditStoreSecurity(
  doc: Document,
  urlStr: string,
): StoreAuditReport {
  const parsedUrl = getSafeDocumentUrl(doc, urlStr);
  const isFileProtocol = parsedUrl ? parsedUrl.protocol === 'file:' : false;
  const isFileDemoScamStore =
    isFileProtocol &&
    Boolean(parsedUrl?.pathname.toLowerCase().includes('demo-tienda-trucha'));
  const safeUrl = parsedUrl
    ? safeTruncate(parsedUrl.href, MAX_URL_LENGTH)
    : safeTruncate(urlStr, MAX_URL_LENGTH);
  const rawHost = parsedUrl ? parsedUrl.hostname.toLowerCase() : '';
  const hostname = rawHost
    ? safeTruncate(rawHost, 256)
    : isFileDemoScamStore
      ? 'urbansneakers-ar.mitiendanube.com'
      : isFileProtocol
        ? 'archivo-local.ar'
        : 'desconocido';
  const isHttps = parsedUrl
    ? parsedUrl.protocol === 'https:' || isFileProtocol
    : false;
  const pageTitle = safeTruncate(
    typeof doc.title === 'string' ? doc.title : '',
    256,
  );

  const typosquatMatch = detectBrandTyposquatting(hostname);
  const hasUserinfoSpoof = hasSuspiciousUrlUserinfo(parsedUrl);
  const dataFiscal = inspectDataFiscalDOM(doc, safeUrl);
  const ecommerce = detectEcommerceContext(
    doc,
    safeUrl,
    dataFiscal,
    typosquatMatch,
  );

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
    combinedBoundedText =
      `${combinedBoundedText}\n${extractFallbackBodyText(doc, 30_000)}`.slice(
        0,
        MAX_SCANNED_TEXT_CHARS,
      );
  }

  const cuits = extractCUITsFromText(combinedBoundedText);
  const validCuits = cuits.filter((c) => c.isValid);
  const invalidCuits = cuits.filter((c) => !c.isValid);

  const findings: AuditFinding[] = [];
  const scoreBreakdown: ScoreBreakdownItem[] = [];

  // =========================================================================
  // BRANCH 0: RAGGIODEV CREATOR EASTER EGG (100/100)
  // =========================================================================
  if (isRaggiodevCreatorHq(parsedUrl) || ecommerce.platform === 'RAGGIODEV_HQ') {
    scoreBreakdown.push(
      {
        label: '🎮 Easter Egg encontrado',
        delta: 90,
        type: 'base',
      },
      {
        label: '✨ Sello Oficial Raggiodev',
        delta: 10,
        type: 'positive',
      },
    );

    findings.push({
      id: 'raggiodev-creator-easter-egg',
      severity: 'SAFE',
      title: '🟢 ¡Easter Egg encontrado! · Perfil Oficial del Creador',
      detail:
        '¡Encontraste un secreto oculto de Escudo Criollo! Estás visitando una web o red oficial de su creador: Raggiodev. Nota: este puntaje es un guiño humorístico y de color para la comunidad 😉.',
      evidence:
        'Easter Egg Desbloqueado · Desarrollado por Raggiodev',
    });

    return {
      url: safeUrl,
      hostname,
      pageTitle,
      isHttps: true,
      timestamp: Date.now(),
      ecommerce,
      trustScore: 100,
      scoreBreakdown,
      riskLevel: 'SAFE',
      pillHeadline: '🎮 Easter Egg encontrado · Raggiodev',
      cuits,
      dataFiscal,
      findings,
    };
  }

  // =========================================================================
  // BRANCH 0B: ANTI-TYPOSQUATTING & URL CREDENTIAL SPOOFING (0/100 DANGER)
  // =========================================================================
  if (typosquatMatch !== null || hasUserinfoSpoof) {
    scoreBreakdown.push(
      {
        label: 'Base inicial comercio auditado',
        delta: SCORING_WEIGHTS.HEURISTIC_ECOMMERCE_BASE,
        type: 'base',
      },
      {
        label:
          'FRAUDE CRÍTICO: Dominio imitador (Typosquatting / Phishing)',
        delta: SCORING_WEIGHTS.CRITICAL_TYPOSQUATTING_PENALTY,
        type: 'negative',
      },
    );

    findings.push({
      id: 'typosquatting-brand-impersonation',
      severity: 'DANGER',
      title: 'Alerta de Phishing: Dominio imitador detectado',
      detail: typosquatMatch
        ? `Este sitio (${hostname}) imita de forma engañosa a la marca oficial ${typosquatMatch.targetBrand} (${typosquatMatch.officialDomain}). No ingreses claves, tarjetas ni realices transferencias.`
        : 'La dirección URL contiene credenciales engañosas (@) para simular otro dominio oficial. Posible ataque de phishing.',
      evidence: typosquatMatch ? typosquatMatch.evidence : safeUrl,
    });

    return {
      url: safeUrl,
      hostname,
      pageTitle,
      isHttps,
      timestamp: Date.now(),
      ecommerce,
      trustScore: 0,
      scoreBreakdown,
      riskLevel: 'DANGER',
      pillHeadline: 'Alerta: Dominio Imitador (Posible Phishing)',
      cuits,
      dataFiscal,
      findings,
    };
  }

  // =========================================================================
  // BRANCH A1: REGULATED FINANCIAL ENTITIES, BROKERS (ALyC) & BANKS (100/100)
  // =========================================================================
  if (ecommerce.platform === 'ENTIDAD_FINANCIERA') {
    scoreBreakdown.push({
      label: 'Base Entidad Financiera / Broker Regulado',
      delta: SCORING_WEIGHTS.VERIFIED_FINANCIAL_BASE,
      type: 'base',
    });
    if (isHttps) {
      scoreBreakdown.push({
        label: 'Conexión cifrada HTTPS',
        delta: SCORING_WEIGHTS.HTTPS_BONUS,
        type: 'positive',
      });
    } else {
      scoreBreakdown.push({
        label: 'Conexión sin cifrado HTTPS',
        delta: -25,
        type: 'negative',
      });
    }
    scoreBreakdown.push({
      label: 'Dominio institucional verificado',
      delta: SCORING_WEIGHTS.VERIFIED_FINANCIAL_DOMAIN_BONUS,
      type: 'positive',
    });

    findings.push({
      id: 'verified-financial-broker-entity',
      severity: 'SAFE',
      title: 'Entidad financiera, broker (ALyC) o billetera oficial',
      detail:
        'Entidad financiera, broker (ALyC) o billetera regulada en su dominio auténtico. Verificá siempre en la barra del navegador que el dominio sea exacto antes de ingresar tus credenciales.',
      evidence: hostname,
    });

    if (validCuits.length > 0) {
      findings.push({
        id: 'valid-cuit-present',
        severity: 'SAFE',
        title: 'CUIT institucional verificado (Módulo 11)',
        detail:
          'El CUIT informado cumple con la validación matemática y prefijo oficial de ARCA/AFIP.',
        evidence: validCuits
          .slice(0, 2)
          .map((c) => c.formatted)
          .join(' · '),
      });
    }

    const trustScore = clampScoreFromBreakdown(scoreBreakdown);
    return {
      url: safeUrl,
      hostname,
      pageTitle,
      isHttps,
      timestamp: Date.now(),
      ecommerce,
      trustScore,
      scoreBreakdown,
      riskLevel: isHttps ? 'SAFE' : 'WARNING',
      pillHeadline: isHttps
        ? 'Entidad Financiera Oficial'
        : 'Precaución · Sitio sin HTTPS',
      cuits,
      dataFiscal,
      findings,
    };
  }

  // =========================================================================
  // BRANCH A2: OFFICIAL MARKETPLACES WITH THIRD-PARTY SELLER ADVISORY (100/100)
  // =========================================================================
  if (ecommerce.platform === 'MARKETPLACE_OFICIAL') {
    scoreBreakdown.push({
      label: 'Base Marketplace Oficial Reconocido',
      delta: SCORING_WEIGHTS.VERIFIED_OFFICIAL_BASE,
      type: 'base',
    });
    if (isHttps) {
      scoreBreakdown.push({
        label: 'Conexión cifrada HTTPS',
        delta: SCORING_WEIGHTS.HTTPS_BONUS,
        type: 'positive',
      });
    } else {
      scoreBreakdown.push({
        label: 'Conexión sin cifrado HTTPS',
        delta: -25,
        type: 'negative',
      });
    }
    scoreBreakdown.push({
      label: 'Dominio oficial verificado',
      delta: 10,
      type: 'positive',
    });

    findings.push(
      {
        id: 'whitelisted-official-marketplace',
        severity: 'SAFE',
        title: 'Plataforma de comercio electrónico oficial',
        detail: 'Plataforma de comercio electrónico auténtica y verificada.',
        evidence: hostname,
      },
      {
        id: 'marketplace-third-party-seller-advisory',
        severity: 'SAFE',
        title: 'Atención: Verificá al vendedor individual',
        detail:
          'Atención en Marketplaces: dentro de esta plataforma operan vendedores externos. Revisá siempre la antigüedad, calificaciones y reputación del vendedor individual antes de comprar.',
      },
    );

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

    const trustScore = clampScoreFromBreakdown(scoreBreakdown);
    return {
      url: safeUrl,
      hostname,
      pageTitle,
      isHttps,
      timestamp: Date.now(),
      ecommerce,
      trustScore,
      scoreBreakdown,
      riskLevel: isHttps ? 'SAFE' : 'WARNING',
      pillHeadline: isHttps
        ? 'Tienda Oficial · Verificá al Vendedor'
        : 'Precaución · Sitio sin HTTPS',
      cuits,
      dataFiscal,
      findings,
    };
  }

  // =========================================================================
  // BRANCH A3: VERIFIED INTERNATIONAL & CROSS-BORDER COURIER PLATFORMS (100/100)
  // =========================================================================
  if (ecommerce.platform === 'ECOMMERCE_INTERNACIONAL') {
    scoreBreakdown.push({
      label: 'Base Plataforma Internacional Reconocida',
      delta: SCORING_WEIGHTS.VERIFIED_INTERNATIONAL_BASE,
      type: 'base',
    });
    if (isHttps) {
      scoreBreakdown.push({
        label: 'Conexión cifrada HTTPS',
        delta: SCORING_WEIGHTS.HTTPS_BONUS,
        type: 'positive',
      });
    } else {
      scoreBreakdown.push({
        label: 'Conexión sin cifrado HTTPS',
        delta: -25,
        type: 'negative',
      });
    }

    findings.push({
      id: 'verified-international-courier-platform',
      severity: 'SAFE',
      title: 'Plataforma internacional o courier verificado',
      detail:
        'Plataforma internacional o courier verificado. Opera bajo normativa internacional / régimen de courier (no requiere formulario F.960 local).',
      evidence: hostname,
    });

    const trustScore = clampScoreFromBreakdown(scoreBreakdown);
    return {
      url: safeUrl,
      hostname,
      pageTitle,
      isHttps,
      timestamp: Date.now(),
      ecommerce,
      trustScore,
      scoreBreakdown,
      riskLevel: isHttps ? 'SAFE' : 'WARNING',
      pillHeadline: isHttps
        ? 'Tienda Internacional Verificada'
        : 'Precaución · Sitio sin HTTPS',
      cuits,
      dataFiscal,
      findings,
    };
  }

  // =========================================================================
  // BRANCH B: VERIFIED NATIONAL ARGENTINE RETAILERS & CACE EVENTS (100/100)
  // =========================================================================
  if (ecommerce.isWhitelistedOfficial && ecommerce.isEcommerce) {
    const hasLiveFiscalInDom =
      dataFiscal.status === 'VERIFIED_OFFICIAL_QR' || validCuits.length > 0;
    const isCaceEvent = ecommerce.platformLabel === 'Evento Oficial CACE';

    scoreBreakdown.push({
      label: 'Base Comercio Oficial Reconocido',
      delta: SCORING_WEIGHTS.VERIFIED_OFFICIAL_BASE,
      type: 'base',
    });
    if (isHttps) {
      scoreBreakdown.push({
        label: 'Conexión cifrada HTTPS',
        delta: SCORING_WEIGHTS.HTTPS_BONUS,
        type: 'positive',
      });
    } else {
      scoreBreakdown.push({
        label: 'Conexión sin cifrado HTTPS',
        delta: -25,
        type: 'negative',
      });
    }

    if (hasLiveFiscalInDom) {
      scoreBreakdown.push({
        label: 'Dominio oficial verificado',
        delta: 8,
        type: 'positive',
      });
      scoreBreakdown.push({
        label: 'Respaldo F.960 Data Fiscal / CUIT en página',
        delta: 2,
        type: 'positive',
      });
    } else {
      scoreBreakdown.push({
        label: 'Dominio oficial verificado',
        delta: 10,
        type: 'positive',
      });
    }

    findings.push({
      id: 'whitelisted-official-argentine-store',
      severity: 'SAFE',
      title: isCaceEvent
        ? 'Portal oficial de evento CACE verificado'
        : 'Comercio oficial argentino verificado',
      detail: isCaceEvent
        ? 'Estás navegando en el portal oficial organizado por la Cámara Argentina de Comercio Electrónico (CACE).'
        : 'Estás comprando en el dominio auténtico de una cadena o comercio oficial reconocido en Argentina.',
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
        evidence: dataFiscal.officialQrUrl
          ? safeTruncate(dataFiscal.officialQrUrl, 120)
          : undefined,
      });
    }

    const trustScore = clampScoreFromBreakdown(scoreBreakdown);
    const pillHeadline = !isHttps
      ? 'Precaución · Sitio sin HTTPS'
      : isCaceEvent
        ? 'Evento Oficial Verificado'
        : validCuits.length > 0
          ? 'Tienda Oficial · CUIT OK'
          : 'Tienda Oficial Verificada';

    return {
      url: safeUrl,
      hostname,
      pageTitle,
      isHttps,
      timestamp: Date.now(),
      ecommerce,
      trustScore,
      scoreBreakdown,
      riskLevel: isHttps ? 'SAFE' : 'WARNING',
      pillHeadline,
      cuits,
      dataFiscal,
      findings,
    };
  }

  // =========================================================================
  // BRANCH C: VERIFIED GOVERNMENT (.gob.ar) & UNIVERSITY PORTALS (100/100)
  // =========================================================================
  if (ecommerce.isWhitelistedOfficial && !ecommerce.isEcommerce) {
    scoreBreakdown.push({
      label: 'Base Organismo / Institución Oficial',
      delta: 90,
      type: 'base',
    });
    if (isHttps) {
      scoreBreakdown.push({
        label: 'Conexión cifrada HTTPS',
        delta: SCORING_WEIGHTS.HTTPS_BONUS,
        type: 'positive',
      });
    } else {
      scoreBreakdown.push({
        label: 'Conexión sin cifrado HTTPS',
        delta: -25,
        type: 'negative',
      });
    }

    findings.push({
      id: 'whitelisted-official-institution',
      severity: 'SAFE',
      title: 'Portal institucional o académico oficial',
      detail:
        'Estás navegando en el dominio auténtico de una institución educativa u organismo oficial argentino.',
      evidence: hostname,
    });

    const trustScore = clampScoreFromBreakdown(scoreBreakdown);
    return {
      url: safeUrl,
      hostname,
      pageTitle,
      isHttps,
      timestamp: Date.now(),
      ecommerce,
      trustScore,
      scoreBreakdown,
      riskLevel: isHttps ? 'SAFE' : 'WARNING',
      pillHeadline: 'Portal Oficial Verificado',
      cuits,
      dataFiscal,
      findings,
    };
  }

  // =========================================================================
  // BRANCH D: HEURISTIC E-COMMERCE STORES & GENERAL WEBSITES (CAPPED AT 95/100)
  // =========================================================================
  scoreBreakdown.push({
    label: ecommerce.isEcommerce
      ? 'Base inicial comercio online'
      : 'Base inicial sitio web general',
    delta: ecommerce.isEcommerce
      ? SCORING_WEIGHTS.HEURISTIC_ECOMMERCE_BASE
      : SCORING_WEIGHTS.GENERAL_WEBSITE_BASE,
    type: 'base',
  });

  if (isHttps) {
    scoreBreakdown.push({
      label: 'Conexión cifrada HTTPS',
      delta: SCORING_WEIGHTS.HTTPS_BONUS,
      type: 'positive',
    });
  } else {
    scoreBreakdown.push({
      label: 'Conexión insegura sin cifrado HTTPS',
      delta: SCORING_WEIGHTS.HTTP_PENALTY,
      type: 'negative',
    });
    findings.push({
      id: 'insecure-http-connection',
      severity: 'WARNING',
      title: 'Conexión no segura (sin cifrado HTTPS)',
      detail:
        'Esta página transmite datos sin cifrado SSL/TLS. No ingreses tarjetas de crédito, claves ni datos personales.',
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
    scoreBreakdown.push({
      label: 'Dominio registrado en NIC Argentina (.ar)',
      delta: SCORING_WEIGHTS.NIC_AR_DOMAIN_BONUS,
      type: 'positive',
    });
    findings.push({
      id: 'nic-ar-registered-domain',
      severity: 'SAFE',
      title: 'Dominio propio registrado en NIC Argentina (.ar)',
      detail:
        'Los dominios .com.ar / .ar requieren titularidad validada mediante Clave Fiscal ante ARCA/AFIP en NIC Argentina.',
      evidence: hostname,
    });
  }

  if (dataFiscal.status === 'VERIFIED_OFFICIAL_QR') {
    scoreBreakdown.push({
      label: 'Sello QR Data Fiscal F.960 oficial verificado',
      delta: SCORING_WEIGHTS.OFFICIAL_QR_F960_BONUS,
      type: 'positive',
    });
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

  if (validCuits.length > 0) {
    scoreBreakdown.push({
      label: 'CUIT válido verificado (Módulo 11)',
      delta: SCORING_WEIGHTS.VALID_CUIT_MOD11_BONUS,
      type: 'positive',
    });
    findings.push({
      id: 'valid-modulo11-cuit',
      severity: 'SAFE',
      title: 'CUIT matemáticamente válido en el sitio',
      detail:
        'Superó el algoritmo Módulo 11 y posee prefijo oficial de ARCA/AFIP. Usá "Central BCRA" para confirmar titularidad antes de transferir.',
      evidence: validCuits
        .slice(0, 3)
        .map((c) => `${c.formatted} (${c.entityLabel})`)
        .join(' · '),
    });
  }

  if (ecommerce.isEcommerce) {
    const contactScanTarget =
      footerText.length > 40 ? footerText : combinedBoundedText;
    const hasPhoneLink =
      doc.querySelector(
        'a[href^="tel:"], a[href*="wa.me/"], a[href*="whatsapp.com/send"]',
      ) !== null;
    const hasContact =
      hasPhoneLink || CONTACT_PHONE_OR_WA_REGEX.test(contactScanTarget);
    const hasAddress = PHYSICAL_ADDRESS_REGEX.test(contactScanTarget);
    const hasRazonSocial = RAZON_SOCIAL_REGEX.test(contactScanTarget);

    if (hasContact || hasAddress || hasRazonSocial) {
      scoreBreakdown.push({
        label: 'Datos de contacto / Dirección en pie de página',
        delta: SCORING_WEIGHTS.FOOTER_CONTACT_LEGAL_BONUS,
        type: 'positive',
      });
    } else {
      findings.push({
        id: 'missing-contact-and-address',
        severity: 'WARNING',
        title: 'Sin dirección física, teléfono ni Razón Social visible',
        detail:
          'No se encontró domicilio comercial, línea de contacto verificable ni Razón Social en el pie de página.',
      });
    }
  }

  let criticalRedFlagsCount = 0;

  // === CRITICAL RED FLAGS (DANGER) ===
  if (dataFiscal.status === 'FORGED_STATIC_SEAL') {
    criticalRedFlagsCount++;
    scoreBreakdown.push({
      label:
        'FRAUDE CRÍTICO: Imagen estática falsa de Data Fiscal sin link oficial',
      delta: SCORING_WEIGHTS.CRITICAL_FORGED_SEAL_PENALTY,
      type: 'negative',
    });
    findings.push({
      id: 'forged-data-fiscal-seal',
      severity: 'DANGER',
      title: 'Sello Data Fiscal ARCA/AFIP falsificado o sin vínculo',
      detail:
        'Se detectó una imagen de Data Fiscal (F.960) pegada de forma estática o con enlace falso que NO valida en afip.gob.ar ni arca.gob.ar. Maniobra típica de tiendas truchas.',
      evidence: dataFiscal.forgedEvidence ?? undefined,
    });
  }

  if (invalidCuits.length > 0) {
    criticalRedFlagsCount++;
    scoreBreakdown.push({
      label: 'FRAUDE CRÍTICO: CUIT inválido que falla Módulo 11',
      delta: SCORING_WEIGHTS.CRITICAL_INVALID_CUIT_PENALTY,
      type: 'negative',
    });
    const sampleBad = invalidCuits[0];
    findings.push({
      id: 'invalid-cuit-modulo11',
      severity: 'DANGER',
      title: 'CUIT inválido o inventado en la página',
      detail:
        'El número de CUIT publicado falla la verificación matemática Módulo 11 o usa dígitos ficticios. Ningún comercio legalmente inscripto tiene un CUIT inválido.',
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
    scoreBreakdown.push({
      label: 'Enlaces a redes sociales vacíos o rotos (href="#")',
      delta: SCORING_WEIGHTS.BROKEN_SOCIAL_LINKS_PENALTY,
      type: 'negative',
    });
    findings.push({
      id: 'broken-footer-social-links',
      severity: 'DANGER',
      title: 'Redes sociales falsas o vacías en el pie de página',
      detail:
        'Los botones de Instagram, Facebook o WhatsApp del footer están rotos, vacíos (href="#") o llevan a la portada sin usuario real.',
      evidence: safeTruncate(brokenSocialLinks.join(' · '), 220),
    });
  }

  const hasFiscalBacking =
    validCuits.length > 0 || dataFiscal.status === 'VERIFIED_OFFICIAL_QR';

  if (
    ecommerce.isEcommerce &&
    !hasFiscalBacking &&
    invalidCuits.length === 0 &&
    dataFiscal.status === 'MISSING_DATA_FISCAL'
  ) {
    scoreBreakdown.push({
      label: 'Sin CUIT ni QR F.960 visible en tienda local',
      delta: SCORING_WEIGHTS.MISSING_FISCAL_DATA_PENALTY,
      type: 'negative',
    });
    findings.push({
      id: 'missing-cuit-and-data-fiscal',
      severity: 'WARNING',
      title: 'Tienda sin CUIT ni QR Data Fiscal F.960 visible',
      detail:
        'El comercio vende online pero no exhibe CUIT ni código QR Data Fiscal de ARCA/AFIP en el pie de página. Exigí el CUIT y verificalo en BCRA antes de transferir.',
    });
  } else if (
    ecommerce.isEcommerce &&
    validCuits.length > 0 &&
    dataFiscal.status === 'MISSING_DATA_FISCAL'
  ) {
    findings.push({
      id: 'cuit-without-qr-seal',
      severity: 'WARNING',
      title: 'CUIT presente pero sin QR Data Fiscal interactivo',
      detail:
        'Informa un CUIT matemáticamente válido, pero no incluye el sello F.960 clickeable hacia ARCA/AFIP. Comprobá que el titular del CBU/CVU coincida con este CUIT.',
    });
  }

  if (ecommerce.isFreeSubdomain && !hasFiscalBacking) {
    scoreBreakdown.push({
      label:
        'Subdominio gratuito (.mitiendanube / .myshopify) sin respaldo fiscal',
      delta: SCORING_WEIGHTS.FREE_SUBDOMAIN_UNVERIFIED_PENALTY,
      type: 'negative',
    });
  }

  const aggressivePromoMatch = AGGRESSIVE_TRANSFER_SCAM_REGEX.exec(
    combinedBoundedText,
  );

  if (ecommerce.isFreeSubdomain && aggressivePromoMatch && !hasFiscalBacking) {
    criticalRedFlagsCount++;
    scoreBreakdown.push({
      label: 'Descuentos agresivos solo por transferencia sin respaldo fiscal',
      delta: SCORING_WEIGHTS.AGGRESSIVE_TRANSFER_DISCOUNT_PENALTY,
      type: 'negative',
    });
    findings.push({
      id: 'free-subdomain-aggressive-transfer',
      severity: 'DANGER',
      title: 'Subdominio gratuito + descuentos agresivos por transferencia',
      detail:
        'Combina un subdominio gratuito sin respaldo fiscal con ofertas agresivas por transferencia o 2x1 masivo. Alerta máxima: las transferencias a CBU/CVU no se pueden revertir.',
      evidence: safeTruncate(aggressivePromoMatch[0], 160),
    });
  } else if (ecommerce.isFreeSubdomain && !aggressivePromoMatch) {
    findings.push({
      id: 'free-unverified-subdomain',
      severity: 'WARNING',
      title: 'Subdominio gratuito sin dominio propio (.com.ar)',
      detail:
        'La tienda opera sobre un subdominio gratuito en lugar de un dominio registrado en NIC.ar. Verificá antigüedad y referencias reales antes de comprar.',
      evidence: hostname,
    });
  } else if (
    ecommerce.isEcommerce &&
    aggressivePromoMatch &&
    !hasFiscalBacking
  ) {
    scoreBreakdown.push({
      label: 'Descuentos agresivos solo por transferencia sin respaldo fiscal',
      delta: SCORING_WEIGHTS.AGGRESSIVE_TRANSFER_DISCOUNT_PENALTY,
      type: 'negative',
    });
    findings.push({
      id: 'aggressive-transfer-unverified',
      severity: 'WARNING',
      title: 'Descuento agresivo por transferencia sin respaldo fiscal',
      detail:
        'Ofrece descuentos muy altos por transferencia bancaria pero no informa CUIT ni QR Data Fiscal. Nunca transfieras sin verificar el CUIT del titular.',
      evidence: safeTruncate(aggressivePromoMatch[0], 160),
    });
  }

  // Enforce 95/100 cap on non-whitelisted heuristic stores (reserving 100/100 for official registries)
  const rawTotal = scoreBreakdown.reduce((acc, item) => acc + item.delta, 0);
  const maxAllowed = ecommerce.isEcommerce
    ? SCORE_CAPS.MAX_HEURISTIC_STORE_SCORE
    : SCORE_CAPS.MAX_OFFICIAL_SCORE;

  if (rawTotal > maxAllowed) {
    scoreBreakdown.push({
      label: 'Tope máximo auditoría heurística local (95/100)',
      delta: maxAllowed - rawTotal,
      type: 'neutral',
    });
  }

  const trustScore = clampScoreFromBreakdown(scoreBreakdown, maxAllowed);

  let riskLevel: RiskLevel;
  let pillHeadline: string;

  if (criticalRedFlagsCount > 0 || (ecommerce.isEcommerce && trustScore < 35)) {
    riskLevel = 'DANGER';
    pillHeadline =
      criticalRedFlagsCount === 1 &&
        dataFiscal.status === 'FORGED_STATIC_SEAL'
        ? 'Alerta: Sello Fiscal Falsificado'
        : 'Alerta: Múltiples Señales de Riesgo';
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
  } else if (trustScore >= 75 && hasFiscalBacking) {
    riskLevel = 'SAFE';
    pillHeadline =
      validCuits.length > 0
        ? 'Sin Señales de Riesgo · CUIT OK'
        : 'Sin Señales de Riesgo · QR Fiscal OK';
  } else {
    riskLevel = 'WARNING';
    pillHeadline =
      dataFiscal.status === 'MISSING_DATA_FISCAL' && validCuits.length === 0
        ? 'Precaución · Sin Data Fiscal'
        : 'Precaución · Verificar Datos';
  }

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
    scoreBreakdown,
    riskLevel,
    pillHeadline,
    cuits,
    dataFiscal,
    findings,
  };
}

export const auditStoreDocument = auditStoreSecurity;
export const detectEcommercePlatform = detectEcommerceContext;
