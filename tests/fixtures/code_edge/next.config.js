// Every header is present, and every value is weak: a header name alone proves nothing.
module.exports = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/(.*)", headers: [
      { key: "Strict-Transport-Security", value: "max-age=0" },
      { key: "Content-Security-Policy", value: "script-src * 'unsafe-eval'" },
      { key: "X-Frame-Options", value: "ALLOWALL" },
      { key: "X-Content-Type-Options", value: "off" },
      { key: "Referrer-Policy", value: "unsafe-url" },
      { key: "Permissions-Policy", value: "camera=()" },
      { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
    ] }];
  },
};
