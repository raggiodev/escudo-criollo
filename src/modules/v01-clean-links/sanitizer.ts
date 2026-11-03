import {
  MAX_URL_LENGTH,
  SanitizeResult,
  parseSafeHttpUrl,
  safeTruncate,
} from '../../types';

// Functional query parameters that must NEVER be stripped
const PRESERVED_FUNCTIONAL_PARAMS = new Set([
  'language',
  'lang',
  'locale',
  'k',
  'q',
  'query',
  'search',
  'id',
  'page',
]);

// Global exact tracking parameters dictionary (matched in lowercase)
const GLOBAL_TRACKING_PARAMS = new Set([
  // Amazon affiliate, search, & ad attribution trackers
  'tag',
  'ref',
  'ref_',
  'pf_rd_r',
  'pf_rd_p',
  'pf_rd_m',
  'pf_rd_s',
  'pf_rd_t',
  'pf_rd_i',
  'pd_rd_r',
  'pd_rd_w',
  'pd_rd_wg',
  'pd_rd_i',
  'pd_rd_plhdr',
  'adgrpid',
  'hvpone',
  'hvptwo',
  'hvadid',
  'hvpos',
  'hvnetw',
  'hvrand',
  'hvqmt',
  'hvdev',
  'hvdvcmdl',
  'hvlocint',
  'hvlocphy',
  'hvtargid',
  'hydadcr',
  'mcid',
  'hvocijid',
  'hvexpln',
  'qid',
  'sr',
  'sprefix',
  'crid',
  'dib',
  'dib_tag',
  'linkcode',
  'camp',
  'creative',
  'creativeasin',
  'ascsubtag',
  'th',
  'psc',
  'content-id',
  'aref',

  // Google Ads, Shopping & Analytics
  'gad_source',
  'gad_campaignid',
  'gclid',
  'gclsrc',
  'dclid',
  'gbraid',
  'wbraid',
  'srsltid',
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'utm_id',
  'utm_reader',
  'utm_name',
  '_ga',
  '_gl',
  '_hsenc',
  '_hsmi',
  'mc_cid',
  'mc_eid',
  'mkt_tok',

  // Meta / Instagram / Facebook / TikTok / X / LinkedIn / Pinterest / Snapchat / Microsoft
  'fbclid',
  'igsh',
  'igshid',
  '__tn__',
  'mibextid',
  'ttclid',
  'tt_medium',
  'tt_content',
  'twclid',
  'msclkid',
  'li_fat_id',
  'epik',
  'sccid',
  'yclid',
  'si',
  'feature',

  // MercadoLibre explicit affiliate & recommendation trackers
  'matt_tool',
  'matt_word',
  'matt_source',
  'matt_campaign',
  'matt_account',
  'tracking_id',
  'pdp_filters',
  'reco_item_pos',
  'reco_backend',
  'reco_backend_type',
  'reco_client',
  'reco_id',
]);

// Prefix rules for tracker families
const TRACKER_KEY_PREFIXES = [
  'utm_',
  'gad_',
  'hvp',
  'hva',
  'hvn',
  'hvr',
  'hvq',
  'hvd',
  'hvl',
  'hvt',
  'hvo',
  'hve',
  'pf_rd_',
  'pd_rd_',
  'matt_',
  'reco_',
  '_ga',
  '_gl',
  '_hs',
  'mc_',
  'pk_',
  'mtm_',
  '__cft__',
] as const;

// MercadoLibre-specific short/ambiguous params (scoped so e.g. YouTube ?v= is never touched)
const MERCADOLIBRE_SCOPED_PARAMS = new Set([
  'c_id',
  'c_uid',
  'deal_id',
  'v',
  't',
  'wid',
  'sid',
  'polycard_client',
]);

const YOUTUBE_TIMESTAMP_REGEX = /^\d+(?:s|m\d*s?|h\d*m?\d*s?)?$/i;

function isYouTubeHost(hostname: string): boolean {
  return (
    hostname === 'youtube.com' ||
    hostname.endsWith('.youtube.com') ||
    hostname === 'youtu.be' ||
    hostname === 'youtube-nocookie.com' ||
    hostname.endsWith('.youtube-nocookie.com')
  );
}

function isAmazonHost(hostname: string): boolean {
  return /(?:^|\.)amazon\.(?:com|es|co\.uk|de|fr|it|ca|nl|se|pl|co\.jp|in|com\.(?:br|mx|au|tr|be))$/i.test(
    hostname,
  );
}

function isMercadoLibreHost(hostname: string): boolean {
  return (
    /(?:^|\.)mercadoli[bv]re\.com(?:\.[a-z]{2})?$/i.test(hostname) ||
    /(?:^|\.)mercadoshops\.com(?:\.[a-z]{2})?$/i.test(hostname)
  );
}

function isTwitterOrXHost(hostname: string): boolean {
  return (
    hostname === 'x.com' ||
    hostname.endsWith('.x.com') ||
    hostname === 'twitter.com' ||
    hostname.endsWith('.twitter.com')
  );
}

function shouldStripQueryParam(
  key: string,
  value: string,
  hostname: string,
): boolean {
  const lowerKey = key.toLowerCase();

  // Preserve YouTube video ID (?v=...) unconditionally
  if (lowerKey === 'v' && isYouTubeHost(hostname)) {
    return false;
  }

  // Handle "t" parameter: ONLY keep "t" on YouTube when it is a valid timestamp!
  if (lowerKey === 't') {
    if (isYouTubeHost(hostname) && YOUTUBE_TIMESTAMP_REGEX.test(value.trim())) {
      return false;
    }
    return true;
  }

  if (PRESERVED_FUNCTIONAL_PARAMS.has(lowerKey)) {
    return false;
  }

  if (GLOBAL_TRACKING_PARAMS.has(lowerKey)) {
    return true;
  }

  for (const prefix of TRACKER_KEY_PREFIXES) {
    if (lowerKey.startsWith(prefix)) {
      return true;
    }
  }

  // X / Twitter share context parameter (?s=20, ?s=46)
  if (lowerKey === 's' && isTwitterOrXHost(hostname)) {
    return true;
  }

  // MercadoLibre short parameters (DEAL_ID, V, T, c_id, c_uid)
  if (isMercadoLibreHost(hostname)) {
    if (
      MERCADOLIBRE_SCOPED_PARAMS.has(lowerKey) ||
      key === 'V' ||
      key === 'T' ||
      key === 'DEAL_ID'
    ) {
      return true;
    }
  } else if (key === 'DEAL_ID') {
    return true;
  }

  return false;
}

/**
 * Strips invasive tracking parameters across Amazon, Google Ads (gad_*), MercadoLibre,
 * Meta/Instagram, TikTok, X, and YouTube, cleans malformed empty query keys (?&),
 * and enforces strict http:/https: protocol whitelisting.
 */
export function sanitizeUrl(rawUrl: string): SanitizeResult {
  const safeOriginal = safeTruncate(rawUrl, MAX_URL_LENGTH);
  const parsed = parseSafeHttpUrl(rawUrl);

  if (!parsed) {
    return {
      originalUrl: safeOriginal,
      cleanUrl: '',
      removedParams: [],
      removedCount: 0,
      isModified: false,
      isValidHttpUrl: false,
    };
  }

  const beforeHref = parsed.href;
  const hostname = parsed.hostname.toLowerCase();
  const removedParams: string[] = [];
  const keysToDelete: string[] = [];
  let cleanedMalformedEmptyKey = false;

  // 1. Clean Amazon /ref=... path segments
  if (isAmazonHost(hostname) && /\/ref=[^/?#]*/i.test(parsed.pathname)) {
    const cleanedPathname = parsed.pathname.replace(/\/ref=[^/?#]*/gi, '');
    parsed.pathname = cleanedPathname || '/';
    removedParams.push('ref (ruta)');
  }

  // 2. Inspect query parameters (including malformed empty keys from leading ?&)
  parsed.searchParams.forEach((value, key) => {
    if (key.trim() === '') {
      keysToDelete.push(key);
      cleanedMalformedEmptyKey = true;
      return;
    }
    if (shouldStripQueryParam(key, value, hostname)) {
      removedParams.push(safeTruncate(key, 64));
      keysToDelete.push(key);
    }
  });

  for (const key of keysToDelete) {
    parsed.searchParams.delete(key);
  }

  // Normalize malformed query delimiters (e.g. leading ?&, &&, trailing &, or bare ?)
  if (
    parsed.search === '?' ||
    parsed.search.startsWith('?&') ||
    parsed.search.includes('&&') ||
    parsed.search.endsWith('&')
  ) {
    parsed.search = parsed.searchParams.toString();
    cleanedMalformedEmptyKey = true;
  }

  // 3. Clean MercadoLibre tracking hash fragments (#polycard_client=...&tracking_id=... or #reco_...)
  if (parsed.hash && parsed.hash.length > 1) {
    const rawHash = parsed.hash.slice(1);
    const lowerHash = rawHash.toLowerCase();
    const isMlTrackingHash =
      lowerHash.includes('polycard_client=') ||
      lowerHash.includes('tracking_id=') ||
      lowerHash.includes('reco_item_pos=') ||
      lowerHash.includes('reco_id=') ||
      lowerHash.includes('matt_tool=') ||
      (isMercadoLibreHost(hostname) &&
        (lowerHash.includes('wid=') ||
          lowerHash.includes('sid=') ||
          lowerHash.includes('search_layout=')));

    if (isMlTrackingHash) {
      if (rawHash.includes('=')) {
        const hashParams = new URLSearchParams(rawHash);
        let extractedAny = false;
        hashParams.forEach((_val, hKey) => {
          if (hKey.trim()) {
            removedParams.push(`#${safeTruncate(hKey, 60)}`);
            extractedAny = true;
          }
        });
        if (!extractedAny) {
          removedParams.push(`#${safeTruncate(rawHash, 60)}`);
        }
      } else {
        removedParams.push(`#${safeTruncate(rawHash, 60)}`);
      }
      parsed.hash = '';
    }
  }

  const cleanUrl = parsed.toString();
  const isModified =
    removedParams.length > 0 ||
    cleanedMalformedEmptyKey ||
    cleanUrl !== beforeHref;

  return {
    originalUrl: safeOriginal,
    cleanUrl,
    removedParams,
    removedCount: removedParams.length,
    isModified,
    isValidHttpUrl: true,
  };
}

export const sanitizeTrackingUrl = sanitizeUrl;
