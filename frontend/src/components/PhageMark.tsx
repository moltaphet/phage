export function PhageMark({ size = 36 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      aria-hidden="true"
    >
      <rect width="64" height="64" rx="4" fill="#12181F" stroke="rgba(232,220,196,0.22)" />
      <polygon points="32,8 46,16 46,32 32,40 18,32 18,16" fill="#C9783A" />
      <circle cx="32" cy="24" r="5.5" fill="#090C10" />
      <rect x="30" y="40" width="4" height="11" rx="1" fill="#5A9A96" />
      <path
        d="M32 51 L21 61 M32 51 L43 61 M32 51 L32 62"
        stroke="#E8DCC4"
        strokeWidth="2.2"
        strokeLinecap="round"
      />
    </svg>
  );
}
