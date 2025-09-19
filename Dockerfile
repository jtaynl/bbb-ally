FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --only=production
COPY server.js ./
EXPOSE 8080
CMD ["node", "server.js"]
