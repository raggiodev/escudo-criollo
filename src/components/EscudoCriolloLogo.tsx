import React, { useId } from 'react';

export interface EscudoCriolloLogoProps {
  size?: number;
  className?: string;
}

/**
 * Official Escudo Criollo v0.2.0 Emblem:
 * Raggiodev Violet-Blue & Gold Shield + Argentine Flag Crest + Sun of May + Argentine Mate & Bombilla.
 */
export const EscudoCriolloLogo: React.FC<EscudoCriolloLogoProps> = ({
  size = 24,
  className = '',
}) => {
  const uid = useId().replace(/:/g, '');
  const violetGradId = `ec-violet-${uid}`;
  const goldGradId = `ec-gold-${uid}`;
  const mateBodyGradId = `ec-mate-${uid}`;
  const innerClipId = `ec-clip-${uid}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={violetGradId} x1="6" y1="4" x2="58" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#4F46E5" />
          <stop offset="52%" stopColor="#7C3AED" />
          <stop offset="100%" stopColor="#2563EB" />
        </linearGradient>
        <linearGradient id={goldGradId} x1="8" y1="4" x2="56" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#FDE68A" />
          <stop offset="50%" stopColor="#F59E0B" />
          <stop offset="100%" stopColor="#D97706" />
        </linearGradient>
        <linearGradient id={mateBodyGradId} x1="20" y1="26" x2="44" y2="50" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#312E81" />
          <stop offset="60%" stopColor="#1E1B4B" />
          <stop offset="100%" stopColor="#0F0C24" />
        </linearGradient>
        <clipPath id={innerClipId}>
          <path d="M32 10L13 16.5V30.8C13 43.4 21.1 52.8 32 56.5C42.9 52.8 51 43.4 51 30.8V16.5L32 10Z" />
        </clipPath>
      </defs>

      {/* Outer Shield with Raggiodev Violet-Blue Gradient & Metallic Gold Rim */}
      <path
        d="M32 4.5L8.5 12.5V30.5C8.5 46.2 18.5 57.6 32 61.5C45.5 57.6 55.5 46.2 55.5 30.5V12.5L32 4.5Z"
        fill={`url(#${violetGradId})`}
        stroke={`url(#${goldGradId})`}
        strokeWidth="3.2"
        strokeLinejoin="round"
      />

      {/* Inner Dark Core & Argentine Flag Crest */}
      <g clipPath={`url(#${innerClipId})`}>
        <rect x="10" y="8" width="44" height="50" fill="#0D0B18" />

        {/* Argentine Flag 3 Bands (Celeste - White - Celeste) */}
        <rect x="10" y="11" width="44" height="7.5" fill="#38BDF8" fillOpacity="0.92" />
        <rect x="10" y="18.5" width="44" height="7" fill="#F8FAFC" fillOpacity="0.95" />
        <rect x="10" y="25.5" width="44" height="7.5" fill="#38BDF8" fillOpacity="0.92" />

        {/* Golden Sun of May at Flag Center */}
        <circle cx="32" cy="22" r="3.4" fill="#F59E0B" />
        <circle cx="32" cy="22" r="2.1" fill="#FDE68A" />
      </g>

      {/* Inner Shield Gold Hairline Frame */}
      <path
        d="M32 10L13 16.5V30.8C13 43.4 21.1 52.8 32 56.5C42.9 52.8 51 43.4 51 30.8V16.5L32 10Z"
        stroke={`url(#${goldGradId})`}
        strokeWidth="1.35"
        strokeOpacity="0.78"
        strokeLinejoin="round"
      />

      {/* Angled Golden Bombilla rising to Top-Right */}
      <path
        d="M33.5 31L43.5 15.5"
        stroke={`url(#${goldGradId})`}
        strokeWidth="3.2"
        strokeLinecap="round"
      />
      <path
        d="M41.8 17.8L45.2 14.2"
        stroke="#FDE68A"
        strokeWidth="3.8"
        strokeLinecap="round"
      />

      {/* Argentine Mate Gourd Body (Calabash + Chiselled Virola + Foot) */}
      <path
        d="M25.5 49.5H38.5L36.5 46H27.5L25.5 49.5Z"
        fill={`url(#${goldGradId})`}
      />
      <path
        d="M20.5 34.5C20.5 42.2 25.3 47.2 32 47.2C38.7 47.2 43.5 42.2 43.5 34.5C43.5 31.3 42.1 28.8 40.3 27.5H23.7C21.9 28.8 20.5 31.3 20.5 34.5Z"
        fill={`url(#${mateBodyGradId})`}
        stroke={`url(#${goldGradId})`}
        strokeWidth="2.2"
      />

      {/* Metallic Gold Virola Rim & Decorative Pampa Band */}
      <ellipse
        cx="32"
        cy="27.5"
        rx="8.8"
        ry="2.5"
        fill="#1E1B4B"
        stroke="#FDE68A"
        strokeWidth="2"
      />
      <path
        d="M21.4 36.2C25 37.9 39 37.9 42.6 36.2"
        stroke="#FBBF24"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  );
};
