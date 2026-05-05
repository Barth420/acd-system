-- Database init for the ACD lab.
-- Creates a users table with weak data so attacks have something interesting to exfiltrate.

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password VARCHAR(128) NOT NULL,  -- intentionally plaintext
    role VARCHAR(32) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO users (username, password, role) VALUES
    ('admin', 'admin123', 'admin'),
    ('alice', 'password', 'user'),
    ('bob', 'qwerty', 'user'),
    ('charlie', 'changeme', 'user')
ON CONFLICT (username) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64),
    action VARCHAR(128),
    src_ip VARCHAR(45),
    ts TIMESTAMP DEFAULT NOW()
);
