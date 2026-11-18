import registriesData from '../../data/verified-registries.json';

export interface TyposquattingMatch {
  targetBrand: string;
  officialDomain: string;
  evidence: string;
}

const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;

const KNOWN_TLD_SUFFIXES = [
  '.com.ar',
  '.net.ar',
  '.org.ar',
  '.gob.ar',
  '.gov.ar',
  '.edu.ar',
  '.tur.ar',
  '.mil.ar',
  '.com.br',
  '.com.mx',
  '.com.co',
  '.co.uk',
  '.capital',
  '.coop',
  '.com',
  '.net',
  '.org',
  '.edu',
  '.gov',
  '.app',
  '.io',
  '.me',
  '.la',
  '.ar',
  '.cl',
  '.es',
] as const;

export function normalizeHostname(rawHostname: string): string {
  if (typeof rawHostname !== 'string') {
    return '';
  }
  return rawHostname.trim().toLowerCase().replace(/\.+$/, '');
}

export function isIpLiteral(hostname: string): boolean {
  if (!hostname) {
    return false;
  }
  return (
    IPV4_REGEX.test(hostname) ||
    hostname.startsWith('[') ||
    hostname.includes(':')
  );
}

/**
 * Strict domain boundary matcher: returns true ONLY when hostname equals candidateDomain
 * or is a proper dot-delimited subdomain of candidateDomain.
 */
export function matchesRegisteredDomain(
  rawHostname: string,
  rawCandidateDomain: string,
): boolean {
  const hostname = normalizeHostname(rawHostname);
  const candidate = normalizeHostname(rawCandidateDomain);

  if (!hostname || !candidate || isIpLiteral(hostname)) {
    return false;
  }

  return hostname === candidate || hostname.endsWith(`.${candidate}`);
}

export function matchesAnyRegisteredDomain(
  rawHostname: string,
  domains: readonly string[],
): boolean {
  const hostname = normalizeHostname(rawHostname);
  if (!hostname || isIpLiteral(hostname)) {
    return false;
  }
  return domains.some((domain) => matchesRegisteredDomain(hostname, domain));
}

/**
 * Detects URL userinfo credential spoofing (e.g., https://mercadolibre.com.ar@evil.com).
 */
export function hasSuspiciousUrlUserinfo(parsedUrl: URL | null): boolean {
  if (!parsedUrl) {
    return false;
  }
  return (
    parsedUrl.username.trim().length > 0 || parsedUrl.password.trim().length > 0
  );
}

const ALL_VERIFIED_DOMAINS: readonly string[] = [
  ...registriesData.caceOfficialEvents,
  ...registriesData.financialAndBrokersAr,
  ...registriesData.marketplacesAr,
  ...registriesData.retailersAr,
  ...registriesData.internationalPlatforms,
  ...registriesData.officialInstitutionsAr,
  ...registriesData.nonEcommerceExclusions,
  'raggiodev.com',
  'raggiodev.github.io',
  'raggiodev.substack.com',
];

function stripKnownTld(hostname: string): string {
  for (const suffix of KNOWN_TLD_SUFFIXES) {
    if (hostname.endsWith(suffix) && hostname.length > suffix.length) {
      return hostname.slice(0, hostname.length - suffix.length);
    }
  }
  const lastDot = hostname.lastIndexOf('.');
  return lastDot > 0 ? hostname.slice(0, lastDot) : hostname;
}

function normalizeHomographs(input: string, oneAs: 'i' | 'l'): string {
  return input
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/0/g, 'o')
    .replace(/1/g, oneAs)
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/[-_]/g, '');
}

function collapseRepeats(input: string): string {
  return input.replace(/(.)\1+/g, '$1');
}

function isWithinOneSubstitutionOrTransposition(
  candidate: string,
  target: string,
): boolean {
  if (target.length < 7 || candidate.length !== target.length) {
    return false;
  }
  let diffs = 0;
  const diffIndices: number[] = [];
  for (let i = 0; i < target.length; i++) {
    if (candidate[i] !== target[i]) {
      diffs++;
      diffIndices.push(i);
      if (diffs > 2) {
        return false;
      }
    }
  }
  if (diffs === 1) {
    return true;
  }
  if (diffs === 2) {
    const i0 = diffIndices[0]!;
    const i1 = diffIndices[1]!;
    return (
      i1 === i0 + 1 &&
      candidate[i0] === target[i1] &&
      candidate[i1] === target[i0]
    );
  }
  return false;
}

/**
 * Detects typosquatting, hyphen-spoofing, homograph substitution, and subdomain spoofing
 * targeting high-value Argentine e-commerce, banking, and broker domains.
 */
export function detectBrandTyposquatting(
  rawHostname: string,
): TyposquattingMatch | null {
  const hostname = normalizeHostname(rawHostname);
  if (
    !hostname ||
    hostname === 'localhost' ||
    hostname === 'archivo-local.ar' ||
    hostname === 'desconocido' ||
    isIpLiteral(hostname)
  ) {
    return null;
  }

  if (
    hostname.endsWith('.gob.ar') ||
    hostname.endsWith('.gov.ar') ||
    hostname.endsWith('.edu.ar') ||
    hostname.endsWith('.mil.ar') ||
    matchesAnyRegisteredDomain(hostname, ALL_VERIFIED_DOMAINS)
  ) {
    return null;
  }

  const stem = stripKnownTld(hostname);
  const labels = stem.split('.').filter(Boolean);
  const candidateChunks = [stem.replace(/\./g, ''), ...labels];

  const brandEntries = Object.entries(registriesData.protectedBrandTokens) as [
    string,
    string[],
  ][];

  for (const [brandToken, officialDomains] of brandEntries) {
    const primaryOfficial = officialDomains[0] ?? brandToken;

    if (brandToken === 'arca') {
      const isArcaImpersonation = labels.some(
        (lbl) =>
          lbl === 'arca' ||
          lbl === 'arca-gob' ||
          lbl === 'arca-afip' ||
          lbl === 'afip-arca' ||
          lbl === 'mi-arca',
      );
      if (isArcaImpersonation) {
        return {
          targetBrand: 'ARCA / AFIP',
          officialDomain: primaryOfficial,
          evidence: `${hostname} imita a ${primaryOfficial}`,
        };
      }
      continue;
    }

    if (brandToken === 'bbva') {
      const isBbvaImpersonation = labels.some(
        (lbl) =>
          lbl === 'bbva' ||
          lbl.startsWith('bbva-') ||
          lbl.endsWith('-bbva') ||
          lbl === 'bancobbva' ||
          lbl === 'bbvabanco',
      );
      if (isBbvaImpersonation) {
        return {
          targetBrand: 'BBVA',
          officialDomain: primaryOfficial,
          evidence: `${hostname} imita a ${primaryOfficial}`,
        };
      }
      continue;
    }

    for (const chunk of candidateChunks) {
      const stripped = chunk.replace(/[-_]/g, '');
      const homoI = normalizeHomographs(chunk, 'i');
      const homoL = normalizeHomographs(chunk, 'l');
      const collapsed = collapseRepeats(stripped);
      const targetCollapsed = collapseRepeats(brandToken);

      if (
        stripped.includes(brandToken) ||
        homoI.includes(brandToken) ||
        homoL.includes(brandToken) ||
        (targetCollapsed.length >= 6 && collapsed === targetCollapsed) ||
        isWithinOneSubstitutionOrTransposition(stripped, brandToken)
      ) {
        return {
          targetBrand: brandToken.toUpperCase(),
          officialDomain: primaryOfficial,
          evidence: `${hostname} imita al dominio oficial ${primaryOfficial}`,
        };
      }
    }
  }

  return null;
}
