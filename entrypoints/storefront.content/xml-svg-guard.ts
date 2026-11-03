/**
 * Pre-bundle safety guard for XML / SVG documents (e.g. image/svg+xml endpoints without .svg extensions).
 * In non-HTML XMLDocuments, `document.createElement('div').style` is `undefined`, which would otherwise crash
 * React 18's module-scope CSS vendor-prefix check if bundled in an IIFE content script.
 */
if (
  typeof document !== 'undefined' &&
  document.contentType !== 'text/html' &&
  typeof document.createElement === 'function'
) {
  try {
    const probe = document.createElement('div') as { style?: unknown };
    if (probe && typeof probe.style === 'undefined') {
      const proto = Object.getPrototypeOf(probe) as Record<string, unknown> | null;
      if (proto && !('style' in proto)) {
        Object.defineProperty(proto, 'style', {
          value: {},
          configurable: true,
          writable: true,
        });
      }
    }
  } catch {
    // Non-fatal in restricted XML sandboxes
  }
}
