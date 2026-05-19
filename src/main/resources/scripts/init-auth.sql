-- 1. Create application user
CREATE USER auth_service_app WITH PASSWORD 'auth_service_pass';

-- 2. Allow DB connection
GRANT CONNECT ON DATABASE auth_service TO auth_service_app;

-- 3. Allow schema usage
GRANT USAGE ON SCHEMA public TO auth_service_app;

-- 4. Grant permissions on existing app table
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE credentials TO auth_service_app;

-- 5. Grant usage on sequence for auto increment id
GRANT USAGE, SELECT ON SEQUENCE credentials_id_seq TO auth_service_app;

-- 6. If Liquibase runs from this user, give access to Liquibase tables too
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE databasechangelog TO auth_service_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE databasechangeloglock TO auth_service_app;