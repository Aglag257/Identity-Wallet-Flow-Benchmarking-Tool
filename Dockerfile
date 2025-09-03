# syntax=docker/dockerfile:1
FROM node:20-bookworm-slim

WORKDIR /app
ENV NODE_ENV=production

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 make g++ ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev

COPY . .

# Defaults
ENV ITER=50 \
    ISSUER_PORT=4000 \
    VERIFIER_PORT=5000 \
    WALLET_PORT=6000 \
    HOST=127.0.0.1  


ENTRYPOINT ["node"]
CMD ["jsonBbsRevised.mjs"]
