const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
];

module.exports = {
  poweredByHeader: false,
  images: { remotePatterns: [{ protocol: "https", hostname: "images.example.com" }] },
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  },
};
