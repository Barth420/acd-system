-- Hierarchy lab database. LAB ONLY: plaintext passwords and an over-privileged worker role are deliberate.
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password VARCHAR(128) NOT NULL,
    role VARCHAR(32) DEFAULT 'user'
);
INSERT INTO users (username, password, role) VALUES
    ('admin', 'admin123', 'admin'), ('alice', 'password', 'user'), ('bob', 'qwerty', 'user'), ('charlie', 'changeme', 'user')
ON CONFLICT (username) DO NOTHING;
INSERT INTO users (username, password, role)
    SELECT 'user' || lpad(i::text, 4, '0'), 'pw' || lpad(i::text, 4, '0'), 'user' FROM generate_series(1, 296) AS i
ON CONFLICT (username) DO NOTHING;

CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name VARCHAR(64), price NUMERIC(8,2));
INSERT INTO products (id, name, price) VALUES (1,'Widget',9.99),(2,'Gadget',14.99),(3,'Sprocket',4.50),(4,'Gizmo',19.00),(5,'Doohickey',7.25)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS orders (id SERIAL PRIMARY KEY, username VARCHAR(64), product_id INT, qty INT);
CREATE TABLE IF NOT EXISTS audit_log (id SERIAL PRIMARY KEY, username VARCHAR(64), action VARCHAR(128), src_ip VARCHAR(45));

-- Generation-0 service keys; the controller's /reset restores exactly these values (see shared/controlstate.py).
CREATE TABLE IF NOT EXISTS secrets (id SERIAL PRIMARY KEY, name VARCHAR(64), value VARCHAR(128));
INSERT INTO secrets (name, value) VALUES
    ('key:product_api', 'lab-key-product_api-gen0'), ('key:order_api', 'lab-key-order_api-gen0'),
    ('key:queue', 'lab-key-queue-gen0'), ('key:search_api', 'lab-key-search_api-gen0');

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'queue_worker') THEN CREATE ROLE queue_worker LOGIN PASSWORD 'worker123'; END IF;
END $$;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO queue_worker;   -- deliberately over-privileged
