import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import {
  extractCUITsFromText,
  formatCUIT,
  inspectDataFiscal,
  inspectDataFiscalDOM,
  isValidCUIT,
  normalizeOfficialAfipQrUrl,
  validateCUIT,
} from '../src/modules/v01-cuit-arca/validator';
import {
  sanitizeTrackingUrl,
  sanitizeUrl,
} from '../src/modules/v01-clean-links/sanitizer';
import {
  auditStoreDocument,
  auditStoreSecurity,
  detectEcommerceContext,
  detectEcommercePlatform,
} from '../src/modules/v01-store-heuristics/detector';
import {
  AuditFinding,
  CuitValidationResult,
  MAX_FIELD_LENGTH,
  ScoreBreakdownItem,
  parseSafeHttpUrl,
  safeTruncate,
} from '../src/types';
import {
  MAX_X_ALERT_TWEET_CHARS,
  buildSafeXAlertTweet,
} from '../src/utils/share';

function createDoc(html: string, url: string): Document {
  const dom = new JSDOM(html, { url });
  return dom.window.document;
}

let passedTests = 0;

function runTest(name: string, fn: () => void): void {
  try {
    fn();
    passedTests++;
    console.log(`  ✅ ${name}`);
  } catch (err) {
    console.error(`  ❌ FALLÓ: ${name}`);
    throw err;
  }
}

async function main(): Promise<void> {
  console.log('\n🛡️  ESCUDO CRIOLLO v0.1.1 (by Raggiodev) — Suite de Verificación Forense\n');

  // =========================================================================
  // 1. ENGINE 1: CUIT MODULO 11 & FORENSIC DATA FISCAL
  // =========================================================================
  console.log('▶ Motor 1: Validación Matemática Módulo 11 (CUIT/CUIL) y Sello F.960 ARCA/AFIP');

  runTest('Valida CUITs reales argentinos y verifica alias exportados', () => {
    assert.equal(inspectDataFiscal, inspectDataFiscalDOM);
    assert.equal(sanitizeTrackingUrl, sanitizeUrl);
    assert.equal(auditStoreDocument, auditStoreSecurity);
    assert.equal(detectEcommercePlatform, detectEcommerceContext);

    assert.equal(isValidCUIT('30-70308853-4'), true);
    assert.equal(isValidCUIT('30703088534'), true);
    assert.equal(isValidCUIT('33-69345023-9'), true);
    assert.equal(isValidCUIT('30-50001091-2'), true);
    assert.equal(formatCUIT('30703088534'), '30-70308853-4');

    const mlResult: CuitValidationResult = validateCUIT('30-70308853-4');
    assert.equal(mlResult.isValid, true);
    assert.equal(mlResult.entityType, 'PERSONA_JURIDICA');
  });

  runTest('Rechaza estrictamente letras o símbolos infiltrados (ej. aaaaa20416s28a0151sssss)', () => {
    const poisonedInput = 'aaaaa20416s28a0151sssss';
    assert.equal(isValidCUIT(poisonedInput), false);

    const detailed: CuitValidationResult = validateCUIT(poisonedInput);
    assert.equal(detailed.isValid, false);
    assert.equal(
      detailed.errorReason,
      'Formato inválido: el CUIT solo puede contener 11 números (sin letras).',
    );

    assert.equal(isValidCUIT('30-70308853-4abc'), false);
    assert.equal(isValidCUIT('CUIT 30-70308853-4'), false);
    assert.equal(isValidCUIT('30/70308853/4'), false);
  });

  runTest('Rechaza CUITs con dígito verificador Módulo 11 erróneo', () => {
    assert.equal(isValidCUIT('30-70308853-9'), false);
    assert.equal(isValidCUIT('30-70308853-0'), false);
    assert.equal(isValidCUIT('33-69345023-1'), false);
  });

  runTest('Rechaza secuencias repetitivas/triviales y prefijos inexistentes', () => {
    assert.equal(isValidCUIT('20000000001'), false);
    assert.equal(isValidCUIT('20-00000000-1'), false);
    assert.equal(isValidCUIT('30-11111111-8'), false);
    assert.equal(isValidCUIT('99-70308853-4'), false);
    assert.equal(isValidCUIT('12-34567890-1'), false);
    assert.equal(isValidCUIT('30-7030885-4'), false);
  });

  runTest('Extrae y deduplica CUITs válidos e inválidos respetando límite de 150 KB', () => {
    const sampleFooter = `
      Razón Social: Ejemplo S.R.L. - CUIT: 30-70308853-4
      Copia repetida: 30703088534
      CUIT trucho inventado: CUIT: 30-70308853-9
    `;
    const extracted: CuitValidationResult[] = extractCUITsFromText(sampleFooter);
    assert.equal(extracted.length, 2);
    assert.equal(
      extracted.some((c: CuitValidationResult) => c.formatted === '30-70308853-4' && c.isValid),
      true,
    );
    assert.equal(
      extracted.some((c: CuitValidationResult) => c.formatted === '30-70308853-9' && !c.isValid),
      true,
    );

    // Performance & 150 KB cap verification: CUIT placed at 200 KB must be ignored
    const hugePadding = 'A'.repeat(180_000);
    const beyondCapText = `${hugePadding} CUIT: 33-69345023-9`;
    const start = performance.now();
    const cappedExtracted = extractCUITsFromText(beyondCapText);
    const elapsed = performance.now() - start;
    assert.equal(cappedExtracted.length, 0);
    assert.ok(elapsed < 100, `Extracción excedió presupuesto de tiempo (${elapsed}ms)`);
  });

  runTest('Detecta QR Data Fiscal F.960 oficial, normaliza response.aspx de CompraGamer y detecta sellos truchos', () => {
    // Case A: Verified Official QR
    const officialDoc = createDoc(
      `<footer>
        <a href="http://qr.afip.gob.ar/?qr=Z0JiTlN1R01WamN6,," target="_blank">
          <img src="/assets/datafiscal.png" alt="Formulario 960 Data Fiscal" />
        </a>
      </footer>`,
      'https://mitiendareal.com.ar/',
    );
    const officialAudit = inspectDataFiscalDOM(officialDoc);
    assert.equal(officialAudit.status, 'VERIFIED_OFFICIAL_QR');
    assert.ok(officialAudit.officialQrUrl?.includes('qr.afip.gob.ar'));

    // Case A2: CompraGamer legacy /clavefiscal/qr/response.aspx?qr=... normalized to public viewer
    const compraGamerQrHref =
      'https://serviciosweb.afip.gob.ar/clavefiscal/qr/response.aspx?qr=2yBvcpJW9wS27AwRBCPy9A,,';
    assert.equal(
      normalizeOfficialAfipQrUrl(new URL(compraGamerQrHref)),
      'http://qr.afip.gob.ar/?qr=2yBvcpJW9wS27AwRBCPy9A,,',
    );
    const cgDoc = createDoc(
      `<footer><a href="${compraGamerQrHref}"><img src="/img/datafiscal.jpg" alt="Data Fiscal" /></a></footer>`,
      'https://compragamer.com/',
    );
    const cgAudit = inspectDataFiscalDOM(cgDoc);
    assert.equal(cgAudit.status, 'VERIFIED_OFFICIAL_QR');
    assert.equal(
      cgAudit.officialQrUrl,
      'http://qr.afip.gob.ar/?qr=2yBvcpJW9wS27AwRBCPy9A,,',
    );

    // Case B1: Static unlinked Data Fiscal image
    const forgedStaticDoc = createDoc(
      `<footer>
        <img src="https://tiendatrucha.mitiendanube.com/img/sello-afip-data-fiscal.jpg" alt="AFIP" />
      </footer>`,
      'https://tiendatrucha.mitiendanube.com/',
    );
    const forgedStaticAudit = inspectDataFiscalDOM(forgedStaticDoc);
    assert.equal(forgedStaticAudit.status, 'FORGED_STATIC_SEAL');

    // Case B2: Data Fiscal image wrapped in dead href="#" or generic homepage without query
    const forgedDeadLinkDoc = createDoc(
      `<footer>
        <a href="javascript:void(0)"><img src="/img/qr_arca.webp" alt="Data Fiscal ARCA" /></a>
      </footer>`,
      'https://estafa-outlet.myshopify.com/',
    );
    assert.equal(inspectDataFiscalDOM(forgedDeadLinkDoc).status, 'FORGED_STATIC_SEAL');

    // Case C: Normal store with "nuestras-marcas.png" must NOT false-positive on "arca"
    const brandImagesDoc = createDoc(
      `<main><img src="/banners/nuestras_marcas.png" alt="Marca Oficial" /></main>`,
      'https://deportes.com.ar/',
    );
    assert.equal(inspectDataFiscalDOM(brandImagesDoc).status, 'MISSING_DATA_FISCAL');
  });

  runTest('Detecta sello F.960 oficial en payloads de hidratación SPA (VTEX / Next.js / Angular) antes de montar el footer', () => {
    const vtexLazyHtml = `
      <!doctype html>
      <html>
        <head><title>Tienda SPA Lazy Footer</title></head>
        <body>
          <main><p>$ 199.999</p><button>Agregar al carrito</button></main>
          <script>
            window.__STATE__ = {
              "FooterSeal.1": {
                "afipQrUrl": "http:\\/\\/qr.afip.gob.ar\\/?qr=eyJ2ZXIiOjEsImN1aXQiOjMwNzAzMDg4NTM0fQ=="
              }
            };
          </script>
        </body>
      </html>
    `;
    const spaDoc = createDoc(vtexLazyHtml, 'https://electrohogar-ejemplo.com.ar/');
    const dfAudit = inspectDataFiscalDOM(spaDoc);
    assert.equal(dfAudit.status, 'VERIFIED_OFFICIAL_QR');
    assert.ok(dfAudit.officialQrUrl?.startsWith('http://qr.afip.gob.ar/?qr='));
  });

  // =========================================================================
  // 2. ENGINE 3: ANTI-TRACKING LINK SANITIZER
  // =========================================================================
  console.log('\n▶ Motor 3: Sanitizador de Enlaces Anti-Rastreo y Whitelist de Protocolos');

  runTest('Limpia URLs complejas de Amazon (19+ rastreadores hv*/tag/ref, ruta /ref= y clave vacía ?&)', () => {
    const dirtyAmazonHome =
      'https://www.amazon.com/?&tag=txacdeesrow-20&ref=pd_sl_26in8pe1n8_e&adgrpid=159368102130&hvpone=&hvptwo=&hvadid=704582710993&hvpos=&hvnetw=g&hvrand=12319020644272931268&hvqmt=e&hvdev=c&hvdvcmdl=&hvlocint=&hvlocphy=9263083&hvtargid=kwd-360364908397&hydadcr=16277_13623325&mcid=a8a52c2c9c1d3cce9e4591c7e5b0f1f9&hvocijid=12319020644272931268--&hvexpln=nav&language=es_US';
    const resHome = sanitizeUrl(dirtyAmazonHome);
    assert.equal(resHome.isValidHttpUrl, true);
    assert.equal(resHome.isModified, true);
    assert.equal(resHome.cleanUrl, 'https://www.amazon.com/?language=es_US');
    assert.ok(
      resHome.removedCount >= 19,
      `Se esperaban >= 19 rastreadores eliminados, se eliminaron ${resHome.removedCount}`,
    );

    const dirtyAmazonProduct =
      'https://www.amazon.com/dp/B09V3KXJPB/ref=sr_1_3?tag=txacdeesrow-20&qid=1730551122&sr=8-3&k=auriculares';
    const resProd = sanitizeUrl(dirtyAmazonProduct);
    assert.equal(resProd.cleanUrl, 'https://www.amazon.com/dp/B09V3KXJPB?k=auriculares');
    assert.ok(resProd.removedParams.includes('ref (ruta)'));

    const malformedOnly = 'https://www.amazon.com/?&language=es_US';
    assert.equal(sanitizeUrl(malformedOnly).cleanUrl, 'https://www.amazon.com/?language=es_US');
  });

  runTest('Limpia parámetros gad_source y gad_campaignid de Google Ads en comercios argentinos (Cetrogar)', () => {
    const dirtyCetrogar =
      'https://www.cetrogar.com.ar/heladera-no-frost.html?gad_source=1&gad_campaignid=11723552608';
    const res = sanitizeUrl(dirtyCetrogar);
    assert.equal(res.isModified, true);
    assert.equal(res.removedCount, 2);
    assert.equal(res.cleanUrl, 'https://www.cetrogar.com.ar/heladera-no-frost.html');
  });

  runTest('Limpia parámetros y hash #polycard_client de MercadoLibre', () => {
    const dirtyMl =
      'https://articulo.mercadolibre.com.ar/MLA-1425364758-termo-acero-_JM?matt_tool=883219&matt_word=oferta&tracking_id=9f8e7d&DEAL_ID=MLA123&V=2&T=abc#polycard_client=search-nordic&position=2&tracking_id=9f8e7d';
    const res = sanitizeUrl(dirtyMl);
    assert.equal(res.isValidHttpUrl, true);
    assert.equal(res.isModified, true);
    assert.equal(
      res.cleanUrl,
      'https://articulo.mercadolibre.com.ar/MLA-1425364758-termo-acero-_JM',
    );
    assert.ok(res.removedCount >= 7);
    assert.ok(res.removedParams.includes('matt_tool'));
    assert.ok(res.removedParams.includes('#polycard_client'));
  });

  runTest('Limpia enlaces de Instagram, Facebook, X y preserva timestamps de YouTube', () => {
    const dirtyIg =
      'https://www.instagram.com/reel/C9xYz123AbC/?igsh=MzRlODBiNWFlZA==&utm_source=ig_web_copy_link';
    const cleanIg = sanitizeUrl(dirtyIg);
    assert.equal(cleanIg.cleanUrl, 'https://www.instagram.com/reel/C9xYz123AbC/');
    assert.equal(cleanIg.removedCount, 2);

    // YouTube: MUST keep ?v=... and timestamp ?t=125s, while stripping si & feature
    const dirtyYt =
      'https://www.youtube.com/watch?v=dQw4w9WgXcQ&si=9x8y7z6w&feature=shared&t=125s';
    const cleanYt = sanitizeUrl(dirtyYt);
    assert.equal(
      cleanYt.cleanUrl,
      'https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=125s',
    );

    // X / Twitter: MUST strip ?s=20 and tracking ?t=token
    const dirtyX =
      'https://x.com/raggiodev/status/185000111222?s=20&t=RandomTrackerToken99';
    const cleanX = sanitizeUrl(dirtyX);
    assert.equal(cleanX.cleanUrl, 'https://x.com/raggiodev/status/185000111222');
  });

  runTest('Bloquea protocolos peligrosos (javascript:, data:, vbscript:, file:)', () => {
    for (const malicious of [
      'javascript:alert(document.domain)',
      'JAVASCRIPT:fetch("https://evil.tld")',
      'data:text/html,<script>alert(1)</script>',
      'vbscript:msgbox(1)',
      'file:///C:/Windows/System32/drivers/etc/hosts',
    ]) {
      assert.equal(parseSafeHttpUrl(malicious), null);
      const res = sanitizeUrl(malicious);
      assert.equal(res.isValidHttpUrl, false);
      assert.equal(res.cleanUrl, '');
    }
  });

  // =========================================================================
  // 3. ENGINE 2: E-COMMERCE DETECTOR, SCAM SCORER & ZERO-TRUST DEFENSES
  // =========================================================================
  console.log('\n▶ Motor 2: Heurísticas Anti-Estafas de Tiendas, Registros Oficiales y Desglose');

  runTest('Reconoce CyberMonday/HotSale (CACE), retailers argentinos y plataformas globales con 100/100 SAFE en HTTPS', () => {
    const minimalSpaShell =
      '<!doctype html><html><head><title>Store</title></head><body><div id="app"></div></body></html>';

    for (const eventUrl of [
      'https://www.cybermonday.com.ar/',
      'https://www.hotsale.com.ar/',
      'https://www.cace.org.ar/',
    ]) {
      const eventDoc = createDoc(minimalSpaShell, eventUrl);
      const eventReport = auditStoreSecurity(eventDoc, eventUrl);
      assert.equal(eventReport.ecommerce.isEcommerce, true);
      assert.equal(eventReport.ecommerce.isWhitelistedOfficial, true);
      assert.equal(eventReport.ecommerce.platformLabel, 'Evento Oficial CACE');
      assert.equal(eventReport.pillHeadline, 'Evento Oficial Verificado');
      assert.equal(eventReport.riskLevel, 'SAFE');
      assert.equal(eventReport.trustScore, 100);
    }

    for (const storeUrl of [
      'https://www.mercadolibre.com.ar/',
      'https://www.compragamer.com/',
      'https://www.cetrogar.com.ar/',
      'https://tiendamia.com.ar/',
      'https://www.amazon.com/',
    ]) {
      const doc = createDoc(minimalSpaShell, storeUrl);
      const report = auditStoreSecurity(doc, storeUrl);
      assert.equal(
        report.ecommerce.isEcommerce,
        true,
        `${storeUrl} debía detectarse como isEcommerce: true`,
      );
      assert.equal(
        report.riskLevel,
        'SAFE',
        `${storeUrl} debía calificarse como SAFE, recibió ${report.riskLevel}`,
      );
      assert.equal(
        report.trustScore,
        100,
        `${storeUrl} debía tener trustScore === 100 en HTTPS, recibió ${report.trustScore}`,
      );
      assert.ok(
        report.scoreBreakdown.length >= 2,
        `${storeUrl} debía incluir scoreBreakdown transparente`,
      );
    }
  });

  runTest('Califica SAFE a tienda argentina verificada con CUIT válido, QR F.960, .com.ar y scoreBreakdown exacto', () => {
    const legitHtml = `
      <!doctype html>
      <html>
        <head>
          <title>Mate & Campo Oficial</title>
          <script src="https://cdn.tiendanube.com/assets/store.js"></script>
        </head>
        <body>
          <main>
            <h1>Termo Media Manija</h1>
            <p class="price">$ 64.900</p>
            <button>Agregar al carrito</button>
          </main>
          <footer>
            <p>Mate y Campo S.R.L. - CUIT: 30-70308853-4</p>
            <p>Av. Corrientes 1850, CABA - WhatsApp: +54 9 11 4455-6677</p>
            <a href="https://www.instagram.com/mateycampo.ar">Instagram</a>
            <a href="https://qr.afip.gob.ar/?qr=eyJ2ZXIiOjEsImN1aXQiOjMwNzAzMDg4NTM0fQ==">
              <img src="/img/data-fiscal.png" alt="Data Fiscal AFIP" />
            </a>
          </footer>
        </body>
      </html>
    `;
    const doc = createDoc(legitHtml, 'https://www.mateycampo.com.ar/productos/termo');
    const ctx = detectEcommerceContext(doc, doc.URL);
    assert.equal(ctx.isEcommerce, true);
    assert.equal(ctx.platform, 'TIENDANUBE');

    const report = auditStoreSecurity(doc, doc.URL);
    assert.equal(report.riskLevel, 'SAFE');
    assert.ok(report.trustScore >= 85, `Score esperado >= 85, recibido ${report.trustScore}`);
    assert.equal(report.pillHeadline, 'Tienda Verificada · CUIT OK');
    assert.ok(
      report.scoreBreakdown.some(
        (item: ScoreBreakdownItem) => item.type === 'base' && item.delta === 60,
      ),
    );
    assert.ok(
      report.scoreBreakdown.some(
        (item: ScoreBreakdownItem) => item.type === 'positive' && item.delta === 20,
      ),
    );
  });

  runTest('Califica WARNING a tienda informal sin CUIT ni Data Fiscal (sin señales truchas)', () => {
    const informalHtml = `
      <!doctype html>
      <html>
        <head><title>Indumentaria Barrial</title></head>
        <body class="woocommerce">
          <main>
            <span class="amount">$ 28.500</span>
            <button>Agregar al carrito</button>
          </main>
          <footer>
            <p>Av. Santa Fe 3200, Buenos Aires - Teléfono 11 5544-3322</p>
            <a href="https://www.instagram.com/indumentariabarrial">Seguinos en Instagram</a>
          </footer>
        </body>
      </html>
    `;
    const doc = createDoc(informalHtml, 'https://indumentariabarrial.com/remera');
    const report = auditStoreSecurity(doc, doc.URL);
    assert.equal(report.ecommerce.platform, 'WOOCOMMERCE');
    assert.equal(report.riskLevel, 'WARNING');
    assert.equal(report.pillHeadline, 'Precaución · Sin Data Fiscal');
  });

  runTest('Califica DANGER a tienda trucha y genera alerta segura en X (<= 230 chars, sin @raggiodev)', () => {
    const scamHtml = `
      <!doctype html>
      <html>
        <head><title>Zapatillas Importadas Outlet</title></head>
        <body>
          <header class="promo-banner">
            🔥 ¡LIQUIDACIÓN TOTAL! 50% OFF por transferencia bancaria y 2x1 en toda la tienda 🔥
          </header>
          <main>
            <p>$ 39.990</p>
            <button>Comprar ahora</button>
          </main>
          <footer>
            <p>CUIT: 30-70308853-9</p>
            <a href="#" aria-label="Instagram"><img src="/icons/instagram.svg" alt="Instagram" /></a>
            <a href="https://instagram.com/">Nuestro IG</a>
            <img src="/assets/datafiscal_afip.png" alt="Sello Data Fiscal AFIP" />
          </footer>
        </body>
      </html>
    `;
    const doc = createDoc(
      scamHtml,
      'https://zapatillas-outlet-oficial.mitiendanube.com/',
    );
    const report = auditStoreSecurity(doc, doc.URL);
    assert.equal(report.riskLevel, 'DANGER');
    assert.ok(report.trustScore <= 15, `Score esperado <= 15, recibido ${report.trustScore}`);
    assert.equal(report.pillHeadline, 'Alerta: Posible Tienda Trucha');

    const findingIds = new Set(
      report.findings.map((f: AuditFinding) => f.id),
    );
    assert.ok(findingIds.has('forged-data-fiscal-seal'));
    assert.ok(findingIds.has('invalid-cuit-modulo11'));
    assert.ok(findingIds.has('broken-footer-social-links'));
    assert.ok(findingIds.has('free-subdomain-aggressive-transfer'));

    const { tweetText, intentUrl } = buildSafeXAlertTweet(report);
    assert.ok(
      tweetText.length <= MAX_X_ALERT_TWEET_CHARS,
      `Tweet excede 230 caracteres (${tweetText.length})`,
    );
    assert.ok(tweetText.endsWith('Detectado con 🛡️ Escudo Criollo'));
    assert.equal(tweetText.toLowerCase().includes('@raggiodev'), false);
    assert.ok(intentUrl.startsWith('https://x.com/intent/tweet?text='));
  });

  runTest('Inmunidad ante DOM Clobbering, caracteres BiDi y truncamiento estricto <= 256 chars', () => {
    const hostileTitle = `\u202E<script>alert("xss")</script>${'X'.repeat(600)}`;
    const clobberedHtml = `
      <!doctype html>
      <html>
        <head><title>${hostileTitle}</title></head>
        <body>
          <form id="footer">
            <input name="URL" value="javascript:alert(1)" />
            <input name="location" value="javascript:alert(1)" />
          </form>
        </body>
      </html>
    `;
    const doc = createDoc(clobberedHtml, 'https://sitio-hostil.com/');
    const report = auditStoreSecurity(doc, 'https://sitio-hostil.com/');

    assert.ok(report.pageTitle.length <= MAX_FIELD_LENGTH);
    assert.equal(report.pageTitle.includes('\u202E'), false);
    assert.equal(safeTruncate('A'.repeat(500)).length, MAX_FIELD_LENGTH);
  });

  // =========================================================================
  // 4. RUNTIME STORAGE & MESSAGE VALIDATION GUARDS
  // =========================================================================
  console.log('\n▶ Seguridad IPC & Storage: Validadores de Tipos en Tiempo de Ejecución');

  // Provide minimal chrome mock before dynamic import of storage.ts (webextension-polyfill check)
  (globalThis as Record<string, unknown>).chrome = {
    runtime: { id: 'escudo-criollo-unit-test-id' },
    storage: {
      local: { get: async () => ({}), set: async () => undefined },
      onChanged: { addListener: () => undefined, removeListener: () => undefined },
    },
  };

  const storageMod = await import('../src/utils/storage');

  runTest('Valida remitente Zero-Trust, scoreBreakdown en StoreAuditReport y rechaza payloads adulterados', () => {
    assert.equal(
      storageMod.isTrustedExtensionSender({ id: 'escudo-criollo-unit-test-id' }),
      true,
    );
    assert.equal(
      storageMod.isTrustedExtensionSender({ id: 'malicious-other-extension' }),
      false,
    );
    assert.equal(storageMod.isTrustedExtensionSender(undefined), false);

    assert.equal(storageMod.validateExtensionMessage({ type: 'UNKNOWN_CMD' }), null);
    assert.equal(
      storageMod.validateExtensionMessage({ type: 'REPORT_STORE_AUDIT', payload: {} }),
      null,
    );
    assert.deepEqual(storageMod.validateExtensionMessage({ type: 'GET_TAB_AUDIT' }), {
      type: 'GET_TAB_AUDIT',
    });

    const cgDoc = createDoc('<html><body></body></html>', 'https://www.compragamer.com/');
    const cgReport = auditStoreSecurity(cgDoc, 'https://www.compragamer.com/');
    const validatedReport = storageMod.validateStoreAuditReport(cgReport);
    assert.notEqual(validatedReport, null);
    assert.ok((validatedReport?.scoreBreakdown.length ?? 0) >= 2);

    const sanitizedSettings = storageMod.validateSettings({
      showFloatingBadge: 'not-a-boolean',
      badgePosition: 'top-center-invalid',
      dismissedDomains: ['TIENDATRUCHA.COM', 12345, null],
    });
    assert.equal(sanitizedSettings.showFloatingBadge, true);
    assert.equal(sanitizedSettings.badgePosition, 'bottom-left');
    assert.deepEqual(sanitizedSettings.dismissedDomains, ['tiendatrucha.com']);
  });

  console.log(`\n✨ ÉXITO TOTAL: ${passedTests}/${passedTests} aserciones forenses v0.1.1 verificadas con 0 errores.\n`);
}

try {
  await main();
} catch (err) {
  console.error('\n💥 Error fatal en la verificación:', err);
  process.exit(1);
}
