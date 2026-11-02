const spacingSteps = [
  0, 0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 20, 24,
  28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 72, 80, 96,
];

const pxSpacing = Object.fromEntries(
  spacingSteps.map((step) => [String(step), step === 0 ? '0px' : `${step * 4}px`]),
);
pxSpacing.px = '1px';

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./entrypoints/**/*.{html,ts,tsx}', './src/**/*.{ts,tsx}'],
  theme: {
    spacing: pxSpacing,
    fontSize: {
      '2xs': ['10px', { lineHeight: '14px' }],
      xs: ['12px', { lineHeight: '16px' }],
      sm: ['14px', { lineHeight: '20px' }],
      base: ['16px', { lineHeight: '24px' }],
      lg: ['18px', { lineHeight: '26px' }],
      xl: ['20px', { lineHeight: '28px' }],
      '2xl': ['24px', { lineHeight: '32px' }],
      '3xl': ['30px', { lineHeight: '36px' }],
    },
    borderRadius: {
      none: '0px',
      sm: '4px',
      DEFAULT: '6px',
      md: '8px',
      lg: '10px',
      xl: '12px',
      '2xl': '16px',
      '3xl': '22px',
      full: '9999px',
    },
    extend: {
      colors: {
        raggio: {
          canvas: '#0D0B18',
          card: '#16122B',
          border: '#2B2354',
          hover: '#1F193D',
          indigo: '#4F46E5',
          violet: '#7C3AED',
          blue: '#2563EB',
          gold: '#FBBF24',
          goldLight: '#FDE68A',
          goldMid: '#F59E0B',
          goldDark: '#D97706',
        },
        semaphore: {
          safeText: '#34D399',
          safeBg: 'rgba(6, 78, 59, 0.65)',
          safeBorder: '#10B981',
          warnText: '#FBBF24',
          warnBg: 'rgba(69, 26, 3, 0.65)',
          warnBorder: '#F59E0B',
          dangerText: '#F87171',
          dangerBg: 'rgba(69, 10, 10, 0.75)',
          dangerBorder: '#EF4444',
        },
      },
      fontFamily: {
        sans: [
          'Inter',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          'sans-serif',
        ],
        mono: [
          '"JetBrains Mono"',
          '"Fira Code"',
          'ui-monospace',
          'SFMono-Regular',
          'Consolas',
          'monospace',
        ],
      },
      backgroundImage: {
        'raggio-brand': 'linear-gradient(135deg, #4F46E5 0%, #7C3AED 55%, #2563EB 100%)',
        'raggio-gold': 'linear-gradient(135deg, #FDE68A 0%, #F59E0B 50%, #D97706 100%)',
      },
      boxShadow: {
        'raggio-gold': '0 0 18px rgba(245, 158, 11, 0.16)',
        'raggio-card': '0 16px 40px rgba(5, 4, 12, 0.72)',
        'raggio-danger': '0 0 22px rgba(239, 68, 68, 0.35)',
      },
      keyframes: {
        dangerPulse: {
          '0%, 100%': {
            boxShadow: '0 0 0 0 rgba(239, 68, 68, 0.45), 0 10px 28px rgba(5, 4, 12, 0.8)',
          },
          '50%': {
            boxShadow: '0 0 0 6px rgba(239, 68, 68, 0), 0 10px 28px rgba(5, 4, 12, 0.8)',
          },
        },
      },
      animation: {
        'danger-pulse': 'dangerPulse 2.4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};

