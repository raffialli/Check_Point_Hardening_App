# syntax=docker/dockerfile:1

# Keep this tag aligned with the Playwright version in package-lock.json.
FROM mcr.microsoft.com/playwright:v1.61.1-noble

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3100 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=pwuser:pwuser server.js ./
COPY --chown=pwuser:pwuser lib ./lib
COPY --chown=pwuser:pwuser public ./public
COPY --chown=pwuser:pwuser scripts ./scripts

USER pwuser

EXPOSE 3100

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3100/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["node", "server.js"]
