CREATE TABLE IF NOT EXISTS projections.dcr_software_statement_jtis1 (
    instance_id TEXT NOT NULL,
    software_statement_iss TEXT NOT NULL,
    software_statement_jti TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (instance_id, software_statement_iss, software_statement_jti)
);

CREATE INDEX IF NOT EXISTS dcr_software_statement_jtis1_expires_at_idx
    ON projections.dcr_software_statement_jtis1 (expires_at);
