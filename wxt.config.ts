import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: ({ browser, manifestVersion }) => {
    const isFirefox = browser === 'firefox';
    const isMv2 = manifestVersion === 2;

    const icons = {
      16: 'icon/16.png',
      32: 'icon/32.png',
      48: 'icon/48.png',
      96: 'icon/96.png',
      128: 'icon/128.png',
    };

    return {
      name: 'Escudo Criollo',
      short_name: 'Escudo Criollo',
      version: '0.2.0',
      description:
        'Escudo 100% local contra tiendas online truchas: valida CUIT (Módulo 11), QR Data Fiscal ARCA/AFIP y limpia links.',
      homepage_url: 'https://escudo-criollo.raggiodev.com',
      author: isFirefox ? 'Raggiodev' : { email: 'contact@raggiodev.com' },
      permissions: ['storage', 'contextMenus', 'activeTab'],
      icons,
      action: {
        default_title: 'Escudo Criollo',
        default_icon: icons,
      },
      content_security_policy: isMv2
        ? "script-src 'self'; object-src 'none';"
        : {
          extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none';",
        },
      ...(isFirefox
        ? {
          browser_specific_settings: {
            gecko: {
              id: 'escudo-criollo@raggiodev.com',
              strict_min_version: '142.0',
              data_collection_permissions: {
                required: ['none'],
              },
            },
          } as Record<string, unknown>,
        }
        : {}),
    };
  },
});