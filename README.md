# 🛡️ Escudo Criollo `v0.2.0` *(Desarrollado por [Raggiodev (Fernando Andres Raggio)](https://raggiodev.com))*

> **El “[Steamcito](https://steamcito.com.ar/)” de la seguridad y privacidad para tus compras online en Argentina y Latinoamérica.**
> Extensión **100% local (Zero-Server)** para **Google Chrome, Microsoft Edge y Mozilla Firefox** diseñada bajo arquitectura **Zero-Trust AppSec**.

🌐 **Sitio Web Oficial & Metodología:** [https://escudo-criollo.raggiodev.com/](https://escudo-criollo.raggiodev.com/)
🧪 **Simulador Interactivo de Tienda Trucha (Demo):** [https://escudo-criollo.raggiodev.com/demo-tienda-trucha.html](https://escudo-criollo.raggiodev.com/demo-tienda-trucha.html)
🔒 **Política de Privacidad Oficial:** [https://escudo-criollo.raggiodev.com/privacidad.html](https://escudo-criollo.raggiodev.com/privacidad.html)
💼 **Autor & Portfolio:** Desarrollado por [Raggiodev (Fernando Andres Raggio)](https://raggiodev.com) · ✉️ [contact@raggiodev.com](mailto:contact@raggiodev.com)

---

## 🎯 Misión del Producto

Así como **[Steamcito](https://steamcito.com.ar/)** revolucionó la transparencia de precios en Argentina inyectando indicadores contextuales directamente en pantalla, **Escudo Criollo** protege de forma preventiva, automática y no intrusiva a compradores y usuarios argentinos y latinoamericanos frente a:

1. **Tiendas online truchas de anuncios** que operan sobre subdominios gratuitos con descuentos irreales solo por transferencia bancaria (CBU/CVU/Alias).
2. **Dominios imitadores (Typosquatting / Phishing)** que suplantan a entidades bancarias, brokers regulados (ALyCs) o grandes cadenas comerciales mediante guiones, homógrafos o subdominios engañosos.
3. **Sellos F.960 Data Fiscal de ARCA/AFIP falsificados** (imágenes estáticas pegadas sin vínculo oficial o con enlaces rotos `href="#"`).
4. **Números de CUIT/CUIL inventados o apócrifos** que fallan la validación matemática **Módulo 11**.
5. **Enlaces plagados de rastreadores comerciales y afiliados** al copiar o compartir direcciones URL.

---

## ✨ Los 4 Motores Forenses (`v0.2.0`)

### 1. Inspector Forense de Sello Data Fiscal F.960 (`src/modules/v01-cuit-arca/validator.ts`)
- Verifica si los sellos Data Fiscal exhibidos en tiendas online enlazan realmente a dominios oficiales (`*.afip.gob.ar` / `*.arca.gob.ar`) con parámetros de validación activos.
- **Acción Directa en ARCA (`🏛️ Verificar Ficha en ARCA ↗`):** Permite abrir la constancia oficial F.960 para confirmar que la Razón Social registrada coincida con la tienda visitada.
- **Soporte de Hidratación SPA:** Escanea `<script type="application/ld+json">`, `<noscript>` y estados de hidratación inline (`window.__STATE__`, Next.js, Angular, VTEX) hasta `150 KB` más puntos de control automáticos post-carga.
- **Normalización Pública de QR (`response.aspx` → `qr.afip.gob.ar`):** Convierte automáticamente enlaces legacy `serviciosweb.afip.gob.ar/clavefiscal/qr/response.aspx?qr=...` al visor público `http://qr.afip.gob.ar/?qr=...` para evitar redirecciones al login de Clave Fiscal.

### 2. Validador Matemático de CUIT/CUIL Módulo 11 (`src/config/scoring-config.ts` & `src/modules/v01-cuit-arca/validator.ts`)
- Verifica los **9 prefijos oficiales de ARCA/AFIP** (`20, 23, 24, 25, 26, 27, 30, 33 y 34`), rechaza secuencias repetitivas de relleno y calcula el dígito verificador exacto mediante el vector de coeficientes `[5, 4, 3, 2, 7, 6, 5, 4, 3, 2]`.
- Rechaza estrictamente cualquier letra o símbolo infiltrado tanto en el motor como en el Auditor Manual.
- Incluye acceso directo en 1 clic a la **Central de Deudores del BCRA**.

### 3. Motor Heurístico Anti-Phishing, Entidades Financieras y Tiendas (`src/modules/v01-store-heuristics/detector.ts` & `domain-matcher.ts`)
- **Registros Oficiales Externalizados (`src/data/verified-registries.json`):**
  - **Entidades Financieras y Brokers Regulados (`ENTIDAD_FINANCIERA`, `100/100 SAFE`):** Reconoce bancos regulados por el BCRA, agentes de liquidación y compensación (ALyCs registrados ante la CNV como InvertirOnline, PPI, Balanz, Bull Market, etc.) y billeteras virtuales en sus dominios auténticos.
  - **Marketplaces Oficiales (`MARKETPLACE_OFICIAL`, `100/100 SAFE`):** Incluye aviso preventivo recordando verificar siempre la reputación y antigüedad del vendedor externo individual dentro de la plataforma.
  - **Comercios Oficiales Argentinos, Eventos CACE, Universidades y Plataformas Internacionales (`100/100 SAFE`).**
- **Detector Anti-Typosquatting (`domain-matcher.ts`):** Detecta dominios imitadores que usan guiones, sustituciones homográficas (`0→o`, `1→l/i`, `rn→m`) o credenciales `@` en la URL para suplantar marcas oficiales (`0/100 DANGER`).
- **Tope Heurístico de `95/100`:** Las tiendas privadas no incluidas en registros oficiales alcanzan un máximo de **`95/100`** (`Sin Señales de Riesgo · CUIT OK`), reservando `100/100` exclusivamente para dominios oficiales verificados.

### 4. Sanitizador Automático de Enlaces Anti-Rastreo & Contador de Caracteres (`src/modules/v01-clean-links/sanitizer.ts`)
- Limpia más de 70 parámetros de seguimiento comercial y fragmentos de rastreo al copiar URLs, preservando parámetros funcionales (`language`, `k`, `q`, `v` y marcas de tiempo `t=125s` en video).
- Incluye en la pestaña **Auditor Manual** un **Contador de Caracteres** en tiempo real (Caracteres, Sin espacios, Palabras, Líneas, límite de post en X/Twitter, peso UTF-8 y detector/limpiador de caracteres invisibles Unicode BiDi).

---

## 📊 Metodología Transparente del Puntaje (`0` a `100`)

Cada veredicto incluye un acordeón interactivo **`📊 ¿De dónde sale este puntaje? (Desglose)`** con la suma exacta:

| Señal / Factor Analizado | Impacto | Aplicación |
| :--- | :---: | :--- |
| **Entidad Financiera / Broker Regulado (ALyC / BCRA)** | **`100 / 100`** | Base financiera (`+88`), HTTPS (`+10`) y dominio institucional regulado (`+2`). |
| **Marketplace Oficial (con Aviso de Vendedor Externo)** | **`100 / 100`** | Base oficial (`+80`), HTTPS (`+10`), dominio (`+10`) y aviso preventivo sobre terceros. |
| **Comercio Oficial Argentino / Evento CACE (HTTPS)** | **`100 / 100`** | Base oficial (`+80`), HTTPS (`+10`) y dominio / respaldo F.960 verificado (`+10`). |
| **Plataforma Internacional / Courier Verificado (HTTPS)** | **`100 / 100`** | Base internacional (`+90`) + HTTPS (`+10`) en plataformas cross-border verificadas. |
| **Organismo Oficial / Universidad (`.gob.ar` / `.edu.ar`)** | **`100 / 100`** | Base institucional (`+90`) + HTTPS (`+10`) en portales gubernamentales y académicos. |
| **Tope Máximo Auditoría Heurística Local** | **`Máx. 95 / 100`** | Límite superior para tiendas privadas no listadas evaluadas por heurística local. |
| **Base Inicial Comercio Online General** | **`+60`** | Punto de partida neutro para tiendas online generales con controles reales de carrito. |
| **Conexión Cifrada HTTPS** | **`+10` / `-30`** | `+10` con HTTPS activo; `-30` si opera sobre HTTP plano sin cifrado. |
| **Dominio Propio en NIC Argentina (`.com.ar` / `.ar`)** | **`+15`** | Requiere titularidad validada con Clave Fiscal ante ARCA/AFIP. |
| **Sello QR Data Fiscal F.960 Oficial Verificado** | **`+20`** | Enlace verificable a `*.afip.gob.ar` o `*.arca.gob.ar`. |
| **CUIT Matemáticamente Válido (Módulo 11 · 9 Prefijos)** | **`+15`** | Supera validación Módulo 11 y prefijo oficial (`20, 23, 24, 25, 26, 27, 30, 33 o 34`). |
| **Datos de Contacto / Dirección / Defensa del Consumidor** | **`+10`** | Teléfono, WhatsApp, domicilio físico, Razón Social o Botón de Arrepentimiento visible. |
| **Sin CUIT ni QR F.960 en Tienda Local** | **`-15`** | Comercio local que no exhibe identificación fiscal. |
| **Subdominio Gratuito sin Respaldo Fiscal** | **`-20`** | `.mitiendanube.com` / `.myshopify.com` / `.empretienda.com.ar` sin CUIT ni QR. |
| **Descuento Agresivo por Transferencia sin Respaldo** | **`-20`** | Ofertas agresivas solo por transferencia o 2x1 masivo sin respaldo fiscal. |
| **Enlaces a Redes Sociales Rotos (`href="#"`)** | **`-25`** | Botones de redes sociales vacíos o apuntando a portadas sin perfil. |
| **FRAUDE CRÍTICO: Sello Data Fiscal Falsificado** | **`-65`** | Imagen de Data Fiscal estática o con enlace falso (dispara `DANGER`). |
| **FRAUDE CRÍTICO: CUIT Inválido (Falla Módulo 11)** | **`-65`** | Número de CUIT inventado que falla Módulo 11 (dispara `DANGER`). |
| **FRAUDE CRÍTICO: Dominio Imitador (Typosquatting / Phishing)** | **`-100` (`0/100`)** | Suplantación de marca oficial mediante guiones, homógrafos o subdominios engañosos. |

---

## 🔒 Garantías de Privacidad y Arquitectura Zero-Trust AppSec

- **Procesamiento 100% Local (Zero-Server):** Escudo Criollo no posee servidores de backend, no recopila historial de navegación, no transmite números de CUIT ni URLs y no incluye telemetría de terceros.
- **Cero Sinks XSS:** Prohibición total de `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `dangerouslySetInnerHTML` y `eval()`. Todo dato extraído del sitio visitado se trunca (`<= 256` caracteres), filtra controles Unicode BiDi y se renderiza como nodos de texto escapados por React.
- **Montaje Perezoso (Lazy Closed Shadow DOM) + CSS Inline (`?inline`):** La interfaz flotante se monta bajo demanda únicamente cuando es necesaria, aislada dentro de un `ShadowRoot` cerrado (`mode: 'closed'`) con inyección CSS en tiempo de compilación.
- **Prevención de ReDoS y DoS de Hilo Principal:** Extracción acotada exclusivamente sobre selectores semánticos con tope estricto de `150 KB` y expresiones regulares en tiempo lineal `O(n)`.
- **Permisos Mínimos MV3 + CSP Estricta:** Solo `storage`, `contextMenus` y `activeTab`, bajo política `script-src 'self'; object-src 'none'; base-uri 'none';`.

---

## 👨‍💻 Autor y Contacto

Desarrollado por **Raggiodev (Fernando Andres Raggio)**:

- 🌐 **Sitio Oficial del Proyecto:** [https://escudo-criollo.raggiodev.com](https://escudo-criollo.raggiodev.com)
- 💼 **Portfolio Oficial:** [https://raggiodev.com](https://raggiodev.com)
- 💻 **GitHub:** [https://github.com/raggiodev](https://github.com/raggiodev)
- 🐦 **X (Twitter):** [https://x.com/raggiodev](https://x.com/raggiodev)
- 💼 **LinkedIn:** [https://www.linkedin.com/in/raggiodev/](https://www.linkedin.com/in/raggiodev/)
- 🔗 **Linktree:** [https://linktr.ee/raggiodev](https://linktr.ee/raggiodev)
- ✉️ **Contacto:** [contact@raggiodev.com](mailto:contact@raggiodev.com)
