import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'Escudo Criollo (by Raggiodev)',
    short_name: 'Escudo Criollo',
    version: '0.1.5',
    description:
      'Escudo 100% local contra tiendas online truchas: valida CUIT (Módulo 11), QR Data Fiscal ARCA/AFIP y limpia links.',
    author: {
      email: 'contact@raggiodev.com',
    },
    homepage_url: 'https://github.com/raggiodev/escudo-criollo',
    permissions: ['storage', 'contextMenus', 'activeTab'],
    icons: {
      16: 'icon/16.png',
      32: 'icon/32.png',
      48: 'icon/48.png',
      96: 'icon/96.png',
      128: 'icon/128.png',
    },
    action: {
      default_title: 'Escudo Criollo · Auditoría Anti-Estafas (by Raggiodev)',
      default_icon: {
        16: 'icon/16.png',
        32: 'icon/32.png',
        48: 'icon/48.png',
        96: 'icon/96.png',
        128: 'icon/128.png',
      },
    },
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none';",
    },
  },
});
