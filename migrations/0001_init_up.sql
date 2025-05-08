CREATE TABLE IF NOT EXISTS "vaults" (
	"id" VARCHAR(255) PRIMARY KEY,
	"name" VARCHAR(255) NOT NULL,
	"description" TEXT,
	"created_at" TIMESTAMP NOT NULL,
	"updated_at" TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS "secrets" (
	"id" VARCHAR(255) PRIMARY KEY,
	"vault_id" VARCHAR(255) REFERENCES "vaults"("id") ON DELETE CASCADE,
	"name" VARCHAR(255) NOT NULL,
	"description" TEXT,
	"key_values" JSONB NOT NULL,
	"created_at" TIMESTAMP NOT NULL,
	"updated_at" TIMESTAMP NOT NULL
);


CREATE TABLE IF NOT EXISTS "users" (
	"id" VARCHAR(255) PRIMARY KEY,
	"login" VARCHAR(255) NOT NULL,
	"password_hash" BYTEA NOT NULL,
	"public_key" BYTEA NOT NULL,
	"private_key_protected" BYTEA NOT NULL,
	"created_at" TIMESTAMP NOT NULL,
	"updated_at" TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS "vault_members" (
	"vault_id" VARCHAR(255) REFERENCES "vaults"("id") ON DELETE CASCADE,
	"user_id" VARCHAR(255) REFERENCES "users"("id") ON DELETE CASCADE,
	"vault_key_protected" BYTEA NOT NULL,
	"created_at" TIMESTAMP NOT NULL
);



CREATE TABLE IF NOT EXISTS "access_rules" (
	"id" VARCHAR(255) PRIMARY KEY,
	"user_id" VARCHAR(255) NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
	"vault_id" VARCHAR(255) NOT NULL REFERENCES "vaults"("id") ON DELETE CASCADE,
	"secret_id" VARCHAR(255) REFERENCES "secrets"("id") ON DELETE CASCADE,
	"description" TEXT,
	"permissions" VARCHAR[] NOT NULL,
	"expires_at" TIMESTAMP,
	"created_at" TIMESTAMP NOT NULL,
	"updated_at" TIMESTAMP NOT NULL
);