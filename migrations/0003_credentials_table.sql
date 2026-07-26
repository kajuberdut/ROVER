-- Migration 0003: Create credentials table for OpenBao metadata tracking

CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    type VARCHAR NOT NULL,
    scope VARCHAR NOT NULL,
    product_id VARCHAR REFERENCES products(id) ON DELETE CASCADE,
    description VARCHAR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_scope_product_name 
ON credentials (scope, COALESCE(product_id, ''), name);
