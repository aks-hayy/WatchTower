FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui ./
ENV WATCHTOWER_API_ORIGIN=http://controller:8000 \
    VITE_WATCHTOWER_API_URL=/api/v1
RUN npm run build

FROM node:22-bookworm-slim AS ui
LABEL org.opencontainers.image.title="WatchTower UI" \
      org.opencontainers.image.description="WatchTower local operator interface" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production \
    NITRO_HOST=0.0.0.0 \
    NITRO_PORT=4173 \
    WATCHTOWER_API_ORIGIN=http://controller:8000 \
    VITE_WATCHTOWER_API_URL=/api/v1
WORKDIR /app
COPY --from=build /app/.output ./.output
RUN groupadd --gid 10001 watchtower \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/watchtower --shell /usr/sbin/nologin watchtower
USER watchtower
EXPOSE 4173
HEALTHCHECK --interval=15s --timeout=4s --start-period=15s --retries=6 CMD node -e "fetch('http://127.0.0.1:4173/api/v1/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", ".output/server/index.mjs"]
