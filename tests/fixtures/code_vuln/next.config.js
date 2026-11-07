module.exports = {
  productionBrowserSourceMaps: true,
  images: { remotePatterns: [{ protocol: "https", hostname: "**" }] },
  experimental: { serverActions: { allowedOrigins: ["*"] } },
};
