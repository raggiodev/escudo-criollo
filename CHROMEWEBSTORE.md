# Chrome Web Store Listing — Escudo Criollo (by Raggiodev)

> Last Updated: 2026-11-02

## Store Listing

**Extension Name** [REQUIRED]
Escudo Criollo (by Raggiodev)

**Short Description** [REQUIRED]
Detectá tiendas online truchas, sellos Data Fiscal ARCA/AFIP falsos y CUITs inválidos, y limpiá links con rastreadores al instante.

**Detailed Description** [REQUIRED]
Escudo Criollo te protege mientras comprás online en Argentina y Latinoamérica alertándote en tiempo real ante tiendas falsas de anuncios, sellos fiscales falsificados, números de CUIT inventados y enlaces con rastreadores ocultos.

Funciones principales:
Verificación automática de tiendas online: Muestra un indicador claro de confianza en pantalla al visitar tiendas virtuales para que sepas si el comercio informa su identidad fiscal antes de hacer una transferencia bancaria.
Detección de sellos Data Fiscal falsos: Comprueba si el código QR F.960 dirige realmente al validador oficial de ARCA/AFIP o si es una imagen pegada para simular legalidad.
Validador matemático de CUIT y CUIL: Verifica al instante cualquier número de CUIT en la página o en el panel manual y ofrece acceso rápido a la Central de Deudores del BCRA.
Limpiador de enlaces anti-rastreo: Elimina parámetros espía y rastreadores comerciales al copiar o compartir enlaces de MercadoLibre, Instagram, Facebook, X, YouTube y TikTok.

Cómo usarlo:
1. Navegá normalmente por cualquier tienda online y observá la insignia de estado (Tienda Verificada, Precaución o Alerta de Posible Tienda Trucha) en la esquina inferior de tu pantalla.
2. Hacé clic en la insignia o en el ícono de Escudo Criollo en la barra del navegador para revisar el puntaje de confianza, copiar el CUIT del comercio o consultar sus antecedentes en el BCRA.
3. Hacé clic derecho sobre cualquier enlace o texto seleccionado para copiar un link limpio sin rastreadores o validar un CUIT al instante.

Privacidad 100% local:
Escudo Criollo analiza todo directamente en tu propio navegador sin servidores intermedios. No recopila, almacena ni transmite tu historial de navegación, compras, CUITs consultados ni datos personales a terceros.

Soporte y código abierto:
Desarrollado por Raggiodev. Reportá sugerencias o consultas en https://github.com/raggiodev/escudo-criollo/issues

**Category** [REQUIRED]
Shopping

**Single Purpose** [REQUIRED]
Audits online stores locally for forged Argentine tax seals and invalid CUIT numbers while stripping tracking parameters from shared shopping and social links.

**Primary Language** [REQUIRED]
Spanish (Latin America)

## Graphics & Assets

| Asset | Dimensions | Status | Filename |
|-------|-----------|--------|----------|
| Store Icon [REQUIRED] | 128×128 PNG | ✅ Ready | `public/icon/128.png` |
| Screenshot 1 [REQUIRED] | 1280×800 or 640×400 | ⬜ Not created | |
| Screenshot 2 [RECOMMENDED] | 1280×800 or 640×400 | ⬜ Not created | |
| Screenshot 3 [RECOMMENDED] | 1280×800 or 640×400 | ⬜ Not created | |
| Small Promo Tile [RECOMMENDED] | 440×280 | ⬜ Not created | |
| Marquee Promo Tile | 1400×560 | ⬜ Not created | |

### Screenshot Notes
- Screenshot 1: Tienda online legítima mostrando la píldora "🛡️ Tienda Verificada · CUIT OK" y la tarjeta forense desplegada con puntaje 96/100.
- Screenshot 2: Simulación educativa de tienda sospechosa mostrando la alerta "🚨 Alerta: Posible Tienda Trucha" por sello Data Fiscal estático sin vínculo oficial y CUIT inválido.
- Screenshot 3: Panel táctico del Popup en la pestaña "Auditor Manual" validando un CUIT y limpiando rastreadores de un enlace de MercadoLibre e Instagram.

## Permissions Justification

| Permission | Type | Justification |
|------------|------|---------------|
| `storage` | permissions | Guarda localmente en el dispositivo las preferencias visuales del usuario (posición de la insignia en pantalla, limpieza automática al copiar enlaces y lista de dominios donde el usuario eligió ocultar la insignia). |
| `contextMenus` | permissions | Agrega dos opciones al menú contextual de clic derecho ("Copiar enlace limpio" sobre enlaces y "Validar CUIT seleccionado" sobre texto resaltado) para auditar datos sin abrir el panel principal. |
| `activeTab` | permissions | Permite consultar el diagnóstico de seguridad y la dirección de la pestaña activa únicamente cuando el usuario hace clic en el ícono de la extensión o acciona una opción del menú contextual. |
| `http://*/*`, `https://*/*` (Content Script) | content_scripts | Permite detectar automáticamente tiendas de comercio electrónico mientras el usuario compra para verificar en el momento si los sellos Data Fiscal F.960 y números de CUIT exhibidos son auténticos o falsificados antes de realizar un pago. |

## Privacy & Data Use

### Data Collection

**Does the extension collect user data?** No

### Data Use Certification
- [x] Data is NOT sold to third parties
- [x] Data is NOT used for purposes unrelated to the extension's core functionality
- [x] Data is NOT used for creditworthiness or lending purposes

## Privacy Policy

**Privacy Policy URL** [REQUIRED]
https://github.com/raggiodev/escudo-criollo/blob/main/PRIVACY.md

## Distribution

**Visibility**: Public
**Regions**: All regions (Primary audience: Argentina & Latin America)

## Developer Info

**Publisher Name** [REQUIRED]
Raggiodev

**Contact Email** [REQUIRED]
security@raggiodev.com

**Support URL / Email** [RECOMMENDED]
https://github.com/raggiodev/escudo-criollo/issues

**Homepage URL** [RECOMMENDED]
https://github.com/raggiodev/escudo-criollo

## Version History

| Version | Date | Changes | Status |
|---------|------|---------|--------|
| 0.1.1 | 2026-11-02 | Validación estricta anti-letras en CUIT, limpieza profunda de enlaces de Amazon y Google Ads (`gad_*`), soporte de hidratación SPA para sellos F.960 Data Fiscal, reconocimiento de comercios nacionales e internacionales verificados, auto-minimizado rápido de 2.5s y desglose transparente de puntaje. | Draft |
| 0.1.0 | 2026-11-02 | Lanzamiento inicial: Validador Módulo 11 de CUIT/CUIL, inspector forense de sellos F.960 Data Fiscal ARCA/AFIP, detector heurístico de tiendas truchas, sanitizador de enlaces anti-rastreo, insignia flotante en página y panel táctico. | Draft |

## Review Notes

### Known Issues / Limitations
- Las páginas internas del navegador (`chrome://`) y la propia Chrome Web Store bloquean por diseño del navegador la inspección de página; el panel informa claramente al usuario y ofrece el Auditor Manual.

