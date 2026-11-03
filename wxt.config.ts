import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'Escudo Criollo (by Raggiodev)',
    short_name: 'Escudo Criollo',
    version: '0.1.1',
    description:
      'Protección 100% local contra tiendas online truchas, sellos Data Fiscal ARCA/AFIP falsificados, CUITs inválidos y links con rastreadores.',
    author: {
      email: 'security@raggiodev.com',
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

