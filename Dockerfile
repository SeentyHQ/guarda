FROM node:22-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run typecheck && npm run build
CMD ["sh", "-c", "npm test && node dist/bin.js --help && node dist/bin.js report npm:example@1.0.0"]
