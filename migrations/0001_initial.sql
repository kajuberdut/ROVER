-- ROVER Initial Schema Migration
-- Generated from src/rover/db/schema.py
-- Phase 3: PostgreSQL migration baseline

CREATE TABLE IF NOT EXISTS scan_jobs (
    id VARCHAR PRIMARY KEY,
    target_url VARCHAR NOT NULL,
    git_ref VARCHAR DEFAULT NULL,
    status VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    results_json VARCHAR DEFAULT NULL,
    error_message VARCHAR DEFAULT NULL,
    resolved_commit VARCHAR DEFAULT NULL,
    resolved_tags VARCHAR DEFAULT NULL,
    target_type VARCHAR DEFAULT 'repo'
);

CREATE TABLE IF NOT EXISTS repositories (
    id VARCHAR PRIMARY KEY,
    url VARCHAR UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS images (
    id VARCHAR PRIMARY KEY,
    name VARCHAR UNIQUE NOT NULL,
    image_hash VARCHAR DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS major_components (
    id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS eol_cache (
    id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    response_json VARCHAR NOT NULL,
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS products (
    id VARCHAR PRIMARY KEY,
    name VARCHAR UNIQUE NOT NULL,
    description VARCHAR DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS releases (
    id VARCHAR PRIMARY KEY,
    product_id VARCHAR,
    name VARCHAR NOT NULL,
    version VARCHAR NOT NULL,
    is_end_of_life BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS release_assets (
    id VARCHAR PRIMARY KEY,
    release_id VARCHAR NOT NULL REFERENCES releases(id),
    asset_type VARCHAR NOT NULL,
    asset_id VARCHAR NOT NULL,
    git_ref VARCHAR DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rel_asset_unique
    ON release_assets (release_id, asset_type, asset_id, COALESCE(git_ref, ''));

CREATE TABLE IF NOT EXISTS semgrep_jobs (
    id VARCHAR PRIMARY KEY,
    target_url VARCHAR NOT NULL,
    git_ref VARCHAR DEFAULT NULL,
    resolved_commit VARCHAR DEFAULT NULL,
    status VARCHAR NOT NULL,
    results_json VARCHAR DEFAULT NULL,
    resolved_tags VARCHAR DEFAULT NULL,
    error_message VARCHAR DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    sub VARCHAR PRIMARY KEY,
    email VARCHAR,
    name VARCHAR,
    role VARCHAR NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE IF NOT EXISTS product_users (
    user_sub VARCHAR NOT NULL REFERENCES users(sub) ON DELETE CASCADE,
    product_id VARCHAR NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    role VARCHAR NOT NULL,
    PRIMARY KEY (user_sub, product_id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id VARCHAR PRIMARY KEY,
    user_sub VARCHAR NOT NULL REFERENCES users(sub) ON DELETE CASCADE,
    name VARCHAR NOT NULL,
    token_hash VARCHAR UNIQUE NOT NULL,
    permission VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ci_image_metadata (
    image_hash VARCHAR PRIMARY KEY,
    repo_uri VARCHAR NOT NULL,
    commit_hash VARCHAR NOT NULL,
    metadata_json VARCHAR DEFAULT '{}',
    image_tags VARCHAR DEFAULT '[]',
    ci_job_url VARCHAR DEFAULT NULL,
    created_by_user_sub VARCHAR DEFAULT NULL,
    created_by_token_id VARCHAR DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
