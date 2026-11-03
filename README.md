# 🛡️ Escudo Criollo `v0.1.4` *(by [Fernando Andres Raggio (Raggiodev)](https://raggiodev.com))*

> **El “[Steamcito](https://steamcito.com.ar/)” de la seguridad y privacidad para tus compras online en Argentina y Latinoamérica.**
> Extensión **100% local (Zero-Server)** para Google Chrome (Manifest V3) diseñada bajo arquitectura **Zero-Trust AppSec**.

🌐 **Sitio Web & Metodología:** [https://raggiodev.github.io/escudo-criollo/](https://raggiodev.github.io/escudo-criollo/)
🧪 **Simulador Interactivo de Tienda Trucha (Demo):** [https://raggiodev.github.io/escudo-criollo/demo-tienda-trucha.html](https://raggiodev.github.io/escudo-criollo/demo-tienda-trucha.html)
🔒 **Política de Privacidad Oficial:** [https://raggiodev.github.io/escudo-criollo/privacidad.html](https://raggiodev.github.io/escudo-criollo/privacidad.html)
💼 **Autor & Portfolio:** [Fernando Andres Raggio (Raggiodev)](https://raggiodev.com) · ✉️ [contact@raggiodev.com](mailto:contact@raggiodev.com)

---

## 🎯 Misión del Producto

Así como **[Steamcito](https://steamcito.com.ar/)** revolucionó la transparencia de precios en Argentina inyectando indicadores contextuales directamente en pantalla, **Escudo Criollo** protege de forma preventiva, automática y no intrusiva a compradores argentinos y latinoamericanos frente a:

1. **Tiendas online truchas de anuncios** (Instagram / Facebook / Google Ads) que operan sobre subdominios gratuitos con descuentos irreales solo por transferencia bancaria (CBU/CVU/Alias).
2. **Sellos F.960 Data Fiscal de ARCA/AFIP falsificados** (imágenes estáticas pegadas sin vínculo oficial o con enlaces rotos `href="#"`).
3. **Números de CUIT/CUIL inventados o apócrifos** que fallan la validación matemática **Módulo 11**.
4. **Enlaces plagados de rastreadores comerciales y afiliados** en MercadoLibre, Amazon, Google Ads (`gad_*`), Instagram, Facebook, TikTok y X.

---

## ✨ Los 4 Motores Forenses (`v0.1.4`)

### 1. Inspector Forense de Sello Data Fiscal F.960 (`src/modules/v01-cuit-arca/validator.ts`)
- Verifica si los sellos Data Fiscal exhibidos en tiendas online enlazan realmente a dominios oficiales (`*.afip.gob.ar` / `*.arca.gob.ar`) con parámetros de validación activos.
- **Soporte de Hidratación SPA:** Escanea `<script type="application/ld+json">`, `<noscript>` y estados de hidratación inline (`window.__STATE__`, Next.js, Angular, VTEX) hasta `150 KB` más puntos de control automáticos post-carga.
- **Normalización Pública de QR (`response.aspx` → `qr.afip.gob.ar`):** Convierte automáticamente enlaces legacy `serviciosweb.afip.gob.ar/clavefiscal/qr/response.aspx?qr=...` (como el utilizado en CompraGamer) al visor público `http://qr.afip.gob.ar/?qr=...` para evitar redirecciones al login de Clave Fiscal.
- **Aislamiento de Plataformas No Comerciales:** Excluye repositorios de código, bloques `<pre>`/`<code>`, tablas de commits y artículos Markdown para cero falsos positivos fuera de tiendas online.

### 2. Validador Matemático de CUIT/CUIL Módulo 11 (`src/modules/v01-cuit-arca/validator.ts`)
- Verifica prefijos oficiales (`20, 23, 24, 25, 26, 27, 30, 33, 34`), rechaza secuencias repetitivas de relleno y calcula el dígito verificador exacto mediante los coeficientes `[5, 4, 3, 2, 7, 6, 5, 4, 3, 2]`.
- Rechaza estrictamente cualquier letra o símbolo infiltrado tanto en el motor como en el Auditor Manual.
- Incluye acceso directo en 1 clic a la **Central de Deudores del BCRA**.

### 3. Detector Heurístico de Tiendas, CyberMonday CACE & Desglose Transparente (`src/modules/v01-store-heuristics/detector.ts`)
- Reconoce automáticamente **Tiendanube, Shopify, WooCommerce, VTEX, PrestaShop, Magento**, tiendas en pesos argentinos (`ARS`), portales oficiales de eventos **CACE** (`cybermonday.com.ar`, `hotsale.com.ar`, `cace.org.ar`), más de **170 cadenas y comercios oficiales argentinos** (`mercadolibre.com.ar`, `shopee.com.ar`, `compragamer.com`, `cetrogar.com.ar`, `fravega.com`, `gadnic.com.ar`, `farmacity.com`, `coto.com.ar`, `carrefour.com.ar`, `jumbo.com.ar`, `easy.com.ar`, `sommiercenter.com`, `assistcard.com`, `aerolineas.com.ar`, `despegar.com.ar`, etc.), **universidades e instituciones oficiales** (`.gob.ar`, `.edu.ar`, `uba.ar`, `palermo.edu`, `utn.edu.ar`, `itba.edu.ar`, bancos) y **plataformas internacionales/couriers** (`amazon.com`, `tiendamia.com.ar`, `aliexpress.com`, `shopee.com`, `shein.com`, `temu.com`, `steampowered.com`, etc.).
- **Auto-Minimizado Rápido y Sticky (`2.5s`):** En tiendas verificadas (`SAFE`), la píldora preventiva se compacta suavemente a un escudo discreto tras `2.5 segundos` y recuerda el estado por dominio.

### 4. Sanitizador Automático de Enlaces Anti-Rastreo (`src/modules/v01-clean-links/sanitizer.ts`)
- Limpia más de 70 parámetros de seguimiento y fragmentos en **MercadoLibre** (`matt_tool`, `tracking_id`, `#polycard_client`), **Amazon** (`tag`, `ref`, `/ref=...`, `hv*`, `pd_rd_*`, `pf_rd_*` y claves vacías `?&`), **Google Ads** (`gad_source`, `gad_campaignid`, `gclid`, `srsltid`), **Instagram/Meta** (`igsh`, `fbclid`), **TikTok** y **X**, preservando parámetros funcionales (`language`, `k`, `q`, `v` y marcas de tiempo `t=125s` en YouTube).

---

## 📊 Metodología Transparente del Puntaje (`0` a `100`)

Cada veredicto incluye un acordeón interactivo **`📊 ¿De dónde sale este puntaje? (Desglose)`** con la suma exacta:

| Señal / Factor Analizado | Impacto | Aplicación |
| :--- | :---: | :--- |
| **Comercio Oficial Argentino / Evento CACE (HTTPS)** | **`100 / 100`** | Base oficial (`+80`), HTTPS (`+10`) y dominio / respaldo F.960 verificado (`+10`). |
| **Plataforma Internacional / Courier Verificado (HTTPS)** | **`100 / 100`** | Base internacional (`+90`) + HTTPS (`+10`) en Amazon, Tiendamia, AliExpress, Shopee, Steam, etc. |
| **Organismo Oficial / Banco / Universidad (`.gob.ar` / `.edu.ar`)** | **`100 / 100`** | Base institucional (`+90`) + HTTPS (`+10`) en portales gubernamentales, bancarios y académicos. |
| **Base Inicial Comercio Online General** | **`+60`** | Punto de partida neutro para tiendas online generales. |
| **Conexión Cifrada HTTPS** | **`+10` / `-30`** | `+10` con HTTPS activo; `-30` si opera sobre HTTP plano sin cifrado. |
| **Dominio Propio en NIC Argentina (`.com.ar` / `.ar`)** | **`+15`** | Requiere titularidad validada con Clave Fiscal ante ARCA/AFIP. |
| **Sello QR Data Fiscal F.960 Oficial Verificado** | **`+20`** | Enlace verificable a `*.afip.gob.ar` o `*.arca.gob.ar`. |
| **CUIT Matemáticamente Válido (Módulo 11)** | **`+15`** | Supera validación Módulo 11 y prefijo oficial. |
| **Datos de Contacto / Dirección / Defensa del Consumidor** | **`+10`** | Teléfono, WhatsApp, domicilio físico, Razón Social o Botón de Arrepentimiento visible. |
| **Sin CUIT ni QR F.960 en Tienda Local** | **`-15`** | Comercio local que no exhibe identificación fiscal. |
| **Subdominio Gratuito sin Respaldo Fiscal** | **`-20`** | `.mitiendanube.com` / `.myshopify.com` / `.empretienda.com.ar` sin CUIT ni QR. |
| **Descuento Agresivo por Transferencia sin Respaldo** | **`-20`** | Ofertas agresivas solo por transferencia o 2x1 masivo sin respaldo fiscal. |
| **Enlaces a Redes Sociales Rotos (`href="#"`)** | **`-25`** | Botones de redes sociales vacíos o apuntando a portadas sin perfil. |
| **FRAUDE CRÍTICO: Sello Data Fiscal Falsificado** | **`-65`** | Imagen de Data Fiscal estática o con enlace falso (dispara `DANGER`). |
| **FRAUDE CRÍTICO: CUIT Inválido (Falla Módulo 11)** | **`-65`** | Número de CUIT inventado que falla Módulo 11 (dispara `DANGER`). |

---

## 🔒 Garantías de Privacidad y Arquitectura Zero-Trust AppSec

- **Procesamiento 100% Local (Zero-Server):** Escudo Criollo no posee servidores de backend, no recopila historial de navegación, no transmite números de CUIT ni URLs y no incluye telemetría de terceros.
- **Cero Sinks XSS:** Prohibición total de `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `dangerouslySetInnerHTML` y `eval()`. Todo dato extraído del sitio visitado se trunca (`<= 256` caracteres), filtra controles Unicode BiDi y se renderiza como nodos de texto escapados por React.
- **Montaje Perezoso (Lazy Closed Shadow DOM) + CSS Inline (`?inline`):** La interfaz flotante se monta bajo demanda únicamente cuando es necesaria, aislada dentro de un `ShadowRoot` cerrado (`mode: 'closed'`) con inyección CSS en tiempo de compilación.
- **Prevención de ReDoS y DoS de Hilo Principal:** Extracción acotada exclusivamente sobre selectores semánticos con tope estricto de `150 KB` y expresiones regulares en tiempo lineal `O(n)`.
- **Permisos Mínimos MV3 + CSP Estricta:** Solo `storage`, `contextMenus` y `activeTab`, bajo política `script-src 'self'; object-src 'none'; base-uri 'none';`.

---

## 👨‍💻 Autor y Contacto

Desarrollado en Argentina por **Fernando Andres Raggio (Raggiodev)**:

- 🌐 **Sitio Oficial:** [https://raggiodev.com](https://raggiodev.com)
- 💻 **GitHub:** [https://github.com/raggiodev](https://github.com/raggiodev)
- 🐦 **X (Twitter):** [https://x.com/raggiodev](https://x.com/raggiodev)
- 💼 **LinkedIn:** [https://www.linkedin.com/in/raggiodev/](https://www.linkedin.com/in/raggiodev/)
- 🔗 **Linktree:** [https://linktr.ee/raggiodev](https://linktr.ee/raggiodev)
- ✉️ **Contacto:** [contact@raggiodev.com](mailto:contact@raggiodev.com)
