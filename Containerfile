# Stage 1: Build and install dependencies
# Use a Node.js UBI image for a consistent Node.js environment and build tools
FROM registry.access.redhat.com/ubi8/nodejs-18 as build

WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker cache
# This ensures that if only app code changes, npm install is not re-run
COPY package*.json ./

# Install production dependencies only. `npm ci` is more reliable for CI/CD.
RUN npm ci --only=production

# Copy all application source code
COPY . .

# Stage 2: Create the final production image
# Use a leaner UBI Node.js image for smaller size in production
FROM registry.access.redhat.com/ubi8/nodejs-18-minimal as production

# Set working directory
WORKDIR /app

# Copy only the necessary files from the build stage
# node_modules and application code
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/proxy.js .
COPY --from=build /app/package.json . # Include package.json for metadata if needed

# Expose the port your app runs on (standard for HTTPS)
EXPOSE 443

# Set default environment variables for the container.
# IMPORTANT: Sensitive variables (DB credentials, JWT_SECRET, ADMIN_SECRET_KEY)
#            should be provided via Kubernetes Secrets at deployment time, NOT hardcoded here.
ENV PORT=443 \
    DB_HOST=your_db_host_placeholder \
    DB_USER=your_db_user_placeholder \
    DB_PASSWORD=your_db_password_placeholder \
    DB_NAME=paywall_db_placeholder \
    JWT_SECRET=your_jwt_secret_placeholder \
    ADMIN_SECRET_KEY=your_admin_secret_placeholder \
    # NEW: Paths where Kubernetes Secrets will mount your TLS certificate files
    TLS_KEY_PATH=/etc/certs/tls.key \
    TLS_CERT_PATH=/etc/certs/tls.crt

# Run as a non-root user for security best practices in containers.
# UBI Node.js images often use UID 1001 for their default user.
# This user needs to have read access to /app and mounted /etc/certs.
USER 1001

# Define the command to run your application
CMD ["node", "proxy.js"]