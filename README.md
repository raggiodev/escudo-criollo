# 🛡️ Escudo Criollo `v0.1.0` *(by Raggiodev)*

Extensión de seguridad y privacidad **100% local (Zero-Server)** para Google Chrome (Manifest V3), diseñada para proteger a compradores de Argentina y Latinoamérica frente a **tiendas online truchas de anuncios**, **sellos F.960 Data Fiscal de ARCA/AFIP falsificados**, **CUITs inválidos** y **enlaces llenos de rastreadores**.

---

## ✨ Motores Principales (`v0.1.0`)

1. **Validador Matemático de CUIT/CUIL & Auditor Forense Data Fiscal (`src/modules/v01-cuit-arca/validator.ts`)**
   - Verificación exacta de dígito verificador **Módulo 11** (`[5, 4, 3, 2, 7, 6, 5, 4, 3, 2]`), prefijos oficiales (`20, 23, 24, 25, 26, 27, 30, 33, 34`) y rechazo de secuencias repetitivas ficticias.
   - Inspección forense del formulario **F.960 Data Fiscal**: distingue códigos QR oficiales que enlazan a `*.afip.gob.ar` / `*.arca.gob.ar` con parámetros activos frente a imágenes estáticas pegadas o con `href="#"` para engañar compradores.

2. **Motor Heurístico de E-Commerce y Detección de Estafas (`src/modules/v01-store-heuristics/detector.ts`)**
   - Reconoce Tiendanube, Shopify, WooCommerce, MercadoLibre, MercadoShops, VTEX, PrestaShop, Magento y tiendas argentinas en ARS.
   - Detecta banderas rojas críticas: subdominios gratuitos combinados con descuentos agresivos solo por transferencia, redes sociales rotas en el pie de página, CUITs apócrifos y ausencia de identificación comercial.

3. **Sanitizador de Enlaces Anti-Rastreo (`src/modules/v01-clean-links/sanitizer.ts`)**
   - Limpia parámetros de seguimiento y fragmentos `#polycard_client` en MercadoLibre, Instagram (`igsh`), Facebook (`fbclid`, `__cft__`), Google/UTM, TikTok, X y YouTube (preservando `v` y marcas de tiempo `t=120s`).

---

## 🔒 Arquitectura Zero-Trust AppSec

- **Cero Sinks XSS:** Prohibición total de `innerHTML`, `dangerouslySetInnerHTML` y `eval()`. Todo dato extraído del sitio visitado se trunca (`<= 256` caracteres), filtra controles BiDi y se renderiza como nodos de texto escapados por React.
- **Closed Shadow DOM + Anti-Tampering:** La insignia estilo *Steamcito* se monta con `mode: 'closed'` para impedir lectura o sabotaje desde scripts de páginas hostiles, con re-montaje seguro único ante borrado del nodo host.
- **Prevención de ReDoS y DoS de Hilo Principal:** Extracción acotada exclusivamente sobre selectores semánticos con tope estricto de `150 KB` y expresiones regulares en tiempo lineal `O(n)`.
- **Permisos Mínimos MV3 + CSP Estricta:** Solo `storage`, `contextMenus` y `activeTab`.

---

## 🚀 Comandos de Desarrollo y Empaquetado

```powershell
# 1. Regenerar íconos PNG Raggiodev (16, 32, 48, 96, 128 px)
npm run icons

# 2. Ejecutar suite automatizada de pruebas unitarias y seguridad
npx tsx scripts/verify-core.ts

# 3. Compilar extensión de producción (.output/chrome-mv3)
npm run build

# 4. Generar paquete ZIP listo para Chrome Web Store (.output/)
npm run zip
```

### Instalación local en Google Chrome
1. Ejecutá `npm run build`.
2. Abrí `chrome://extensions` en Google Chrome y activá el **Modo de desarrollador**.
3. Hacé clic en **Cargar descomprimida** y seleccioná la carpeta `.output/chrome-mv3`.

---

Desarrollado con orgullo argentino por **Raggiodev** · *100% Local & Open Source*.
