CREATE DATABASE IF NOT EXISTS paywall_db;

USE paywall_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_identifier VARCHAR(255) UNIQUE NOT NULL, -- e.g., user's email or a unique ID from your subscription manager
    api_key VARCHAR(255) UNIQUE NOT NULL,        -- The unique API key for this user
    subscription_status ENUM('active', 'inactive', 'trialing', 'canceled') DEFAULT 'inactive',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Optional: Add an index for faster API key lookups
CREATE INDEX idx_api_key ON users (api_key);