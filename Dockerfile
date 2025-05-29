# Stage 1: Build and install dependencies
FROM registry.access.redhat.com/ubi8/nodejs-18
WORKDIR /usr/src/app
COPY package*.json ./
COPY Proxy.js ./
RUN npm ci --only=production
COPY . .
# RUN npm install express http-proxy-middleware cookie-parser jsonwebtoken mysql2 express-rate-limit
EXPOSE 80
ENV PORT=80 \
    DB_HOST=paywall-db-instance.cgtocec8e3eg.us-east-1.rds.amazonaws.com \
    DB_USER=admin \
    DB_PASSWORD=9YV0qfWuJkkoJHyP7h5a \
    DB_NAME=paywall_db \
    JWT_SECRET=13e0d79df4dc784bc808832fd00c77e8fedbc20a1f114ed98317d0de5383e840cret_placeholder \
    ADMIN_SECRET_KEY=43cc3acc34b59a930bc6dd52ba89c85d \
    PUBLIC_PROXY_HOST=paywall-proxy-alb-2031279468.us-east-1.elb.amazonaws.com
CMD ["bash"]
