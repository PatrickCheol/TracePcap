FROM node:22-bookworm-slim

ARG CODEX_VERSION=0.163.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global @openai/codex@${CODEX_VERSION} \
    && npm cache clean --force \
    && mkdir -p /home/node/.codex /app/empty \
    && chown -R node:node /home/node/.codex /app

WORKDIR /app
COPY --chown=node:node package.json server.mjs ./
COPY --chown=node:node public ./public
USER node
ENV CODEX_HOME=/home/node/.codex HOST=0.0.0.0 PORT=8787
EXPOSE 8787
CMD ["node", "server.mjs"]
