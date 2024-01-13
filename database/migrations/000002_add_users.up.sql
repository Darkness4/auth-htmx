BEGIN TRANSACTION;
-- https://github.com/go-webauthn/webauthn/blob/79504a21dbeefdf8a694ae5735d4ecbc2bcc1807/webauthn/types.go#L171
CREATE TABLE IF NOT EXISTS users (
  id BLOB NOT NULL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  display_name VARCHAR(255) NOT NULL
);
-- https://github.com/go-webauthn/webauthn/blob/79504a21dbeefdf8a694ae5735d4ecbc2bcc1807/webauthn/credential.go
CREATE TABLE IF NOT EXISTS credentials (
  id BLOB NOT NULL,
  public_key BLOB NOT NULL,
  attestation_type TEXT NOT NULL,
  transport BLOB NOT NULL, --JSON
  flags BLOB NOT NULL, --JSON
  authenticator BLOB NOT NULL, --JSON
  user_id BLOB NOT NULL, -- Relationship is One User to Many credentials
  PRIMARY KEY(id, user_id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
COMMIT;
