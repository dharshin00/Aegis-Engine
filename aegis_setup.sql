-- ==============================================================================
-- Project Aegis: Insider Threat Detection System - Database Setup Scripts
-- ==============================================================================

-- 1. Create the Audit Schema
CREATE SCHEMA IF NOT EXISTS audit;

-- 2. Create the Change Log Table
-- This table securely stores query logs and event context.
CREATE TABLE IF NOT EXISTS audit.change_log (
    log_id SERIAL PRIMARY KEY,
    event_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_name TEXT DEFAULT current_user,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    query TEXT,
    payload JSONB
);

-- 3. Create the Honeytoken Registry Table
-- A highly sensitive-looking table designed to act as a trap for unauthorized access.
CREATE TABLE IF NOT EXISTS audit.honeytoken_registry (
    id SERIAL PRIMARY KEY,
    sensitive_data_1 TEXT,
    sensitive_data_2 TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert deceptive dummy data (Honeytokens)
INSERT INTO audit.honeytoken_registry (sensitive_data_1, sensitive_data_2)
VALUES 
    ('CONFIDENTIAL_KEY_A', 'b9f0868f-4d6d-4952-8703-a1f298c760aa'),
    ('ADMIN_CREDENTIAL_B', 'e4a2b97c-9b8e-4a61-9c12-3f8d7b6a5c4d');

-- 4. Create the advanced PL/pgSQL trigger function
-- Trigger function that logs the access and uses pg_notify to send JSON payload
CREATE OR REPLACE FUNCTION audit.notify_honeytoken_access()
RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
    user_name TEXT;
    event_time TIMESTAMP WITH TIME ZONE;
    operation TEXT;
    old_record JSON;
    new_record JSON;
BEGIN
    user_name := current_user;
    event_time := CURRENT_TIMESTAMP;
    operation := TG_OP;

    -- Handle ROW vs STATEMENT level context gathering for OLD and NEW records
    IF TG_LEVEL = 'ROW' THEN
        IF TG_OP = 'DELETE' OR TG_OP = 'UPDATE' THEN
            old_record := row_to_json(OLD);
        END IF;
        IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
            new_record := row_to_json(NEW);
        END IF;
    END IF;

    -- Construct the JSON payload with comprehensive event context
    payload := json_build_object(
        'event_time', event_time,
        'user_name', user_name,
        'table_name', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
        'operation', operation,
        'old_record', old_record,
        'new_record', new_record,
        'application_name', current_setting('application_name', true),
        'client_addr', inet_client_addr(),
        'client_port', inet_client_port()
    );

    -- Persist the access attempt to the change_log table
    INSERT INTO audit.change_log (user_name, table_name, operation, query, payload)
    VALUES (user_name, TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, operation, current_query(), payload::jsonb);

    -- Asynchronously send the JSON payload to the 'db_event' channel
    PERFORM pg_notify('db_event', payload::text);

    -- Return logic depending on the trigger execution level and operation
    IF TG_LEVEL = 'ROW' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    
    RETURN NULL; -- For statement level triggers
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
-- SECURITY DEFINER ensures the trigger runs with the privileges of the function owner,
-- preventing privilege escalation while allowing logging for lower privileged users.

-- 5. Bind the trigger to the honeytoken_registry table
-- Note: Standard PostgreSQL triggers do not fire on SELECT queries. 
-- For SELECT auditing, use standard PostgreSQL logging (log_statement='all'), 
-- or enable the 'pgaudit' extension. The triggers below handle DML (Insert/Update/Delete/Truncate).

DROP TRIGGER IF EXISTS trg_honeytoken_access_row ON audit.honeytoken_registry;
CREATE TRIGGER trg_honeytoken_access_row
AFTER INSERT OR UPDATE OR DELETE
ON audit.honeytoken_registry
FOR EACH ROW
EXECUTE FUNCTION audit.notify_honeytoken_access();

DROP TRIGGER IF EXISTS trg_honeytoken_access_stmt ON audit.honeytoken_registry;
CREATE TRIGGER trg_honeytoken_access_stmt
AFTER TRUNCATE
ON audit.honeytoken_registry
FOR EACH STATEMENT
EXECUTE FUNCTION audit.notify_honeytoken_access();

-- End of Setup Script
