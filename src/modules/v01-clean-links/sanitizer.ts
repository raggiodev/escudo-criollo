import {
  MAX_URL_LENGTH,
  SanitizeResult,
  parseSafeHttpUrl,
  safeTruncate,
} from '../../types';

// Global cross-platform tracking parameters (safe to strip on all domains, matched in lowercase)
const GLOBAL_TRACKING_PARAMS = new Set([
  // UTM & Analytics
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
  // Ad Click IDs
  'gclid',
  'gclsrc',
  'dclid',
  'wbraid',
  'gbraid',
  'fbclid',
  'msclkid',
  'twclid',
  'ttclid',
  'yclid',
  // Meta / Instagram / Facebook
  'igsh',
  'igshid',
  '__tn__',
  'mibextid',
  // TikTok / Spotify / Social share trackers
  'tt_medium',
  'tt_content',
  'si',
  'feature',
  // MercadoLibre explicit affiliate & reco trackers (unambiguous globally)
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

// MercadoLibre-specific short/ambiguous params (scoped to MercadoLibre/MercadoShops so e.g. YouTube ?v= is never touched)
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

  if (
    GLOBAL_TRACKING_PARAMS.has(lowerKey) ||
    lowerKey.startsWith('utm_') ||
    lowerKey.startsWith('matt_') ||
    lowerKey.startsWith('reco_') ||
    lowerKey.startsWith('__cft__')
  ) {
    return true;
  }

  // Handle "t" parameter: ONLY keep "t" on YouTube when it is a valid timestamp!
  if (lowerKey === 't') {
    if (isYouTubeHost(hostname) && YOUTUBE_TIMESTAMP_REGEX.test(value.trim())) {
      return false;
    }
    return true;
  }

  // X / Twitter share context parameter (?s=20, ?s=46)
  if (lowerKey === 's' && isTwitterOrXHost(hostname)) {
    return true;
  }

  // MercadoLibre short parameters (DEAL_ID, V, T, c_id, c_uid)
  if (isMercadoLibreHost(hostname)) {
    if (MERCADOLIBRE_SCOPED_PARAMS.has(lowerKey) || key === 'V' || key === 'T' || key === 'DEAL_ID') {
      return true;
    }
  } else if (key === 'DEAL_ID') {
    return true;
  }

  return false;
}

/**
 * Strips invasive tracking parameters and MercadoLibre polycard/tracking hash fragments
 * while enforcing strict http:/https: protocol whitelisting.
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

  const hostname = parsed.hostname.toLowerCase();
  const removedParams: string[] = [];
  const keysToDelete: string[] = [];

  parsed.searchParams.forEach((value, key) => {
    if (shouldStripQueryParam(key, value, hostname)) {
      removedParams.push(safeTruncate(key, 64));
      keysToDelete.push(key);
    }
  });

  for (const key of keysToDelete) {
    parsed.searchParams.delete(key);
  }

  // Clean MercadoLibre tracking hash fragments (#polycard_client=...&tracking_id=... or #reco_...)
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
          removedParams.push(`#${safeTruncate(hKey, 60)}`);
          extractedAny = true;
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
  const isModified = removedParams.length > 0 && cleanUrl !== parsed.href ? true : removedParams.length > 0;

  return {
    originalUrl: safeOriginal,
    cleanUrl,
    removedParams,
    removedCount: removedParams.length,
    isModified,
    isValidHttpUrl: true,
  };
}

