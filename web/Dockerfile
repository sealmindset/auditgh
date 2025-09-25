# Build stage
FROM public.ecr.aws/docker/library/node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# Prefer npm ci when lock is in sync; otherwise fall back to npm install
RUN if [ -f package-lock.json ]; then \
      npm ci --no-audit --no-fund || (echo 'npm ci failed, falling back to npm install' && npm install --no-audit --no-fund); \
    else \
      npm install --no-audit --no-fund; \
    fi
COPY . .
RUN npm run build

# Serve stage
FROM public.ecr.aws/docker/library/nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY ./nginx/default.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
