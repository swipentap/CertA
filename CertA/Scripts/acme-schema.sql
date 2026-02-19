-- ACME (RFC 8555) tables for CertA
-- Run after schema.sql

-- ACME Accounts (identified by account key JWK)
CREATE TABLE IF NOT EXISTS "AcmeAccounts" (
    "Id" SERIAL PRIMARY KEY,
    "AccountId" TEXT NOT NULL UNIQUE,
    "KeyJwk" JSONB NOT NULL,
    "KeyThumbprint" TEXT NOT NULL,
    "Status" TEXT NOT NULL DEFAULT 'valid',
    "CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS "IX_AcmeAccounts_AccountId" ON "AcmeAccounts" ("AccountId");
CREATE UNIQUE INDEX IF NOT EXISTS "IX_AcmeAccounts_KeyThumbprint" ON "AcmeAccounts" ("KeyThumbprint");

-- ACME Orders
CREATE TABLE IF NOT EXISTS "AcmeOrders" (
    "Id" SERIAL PRIMARY KEY,
    "OrderId" TEXT NOT NULL UNIQUE,
    "AccountId" TEXT NOT NULL,
    "Identifiers" JSONB NOT NULL,
    "Status" TEXT NOT NULL,
    "Expires" TIMESTAMPTZ NOT NULL,
    "CertificateId" INTEGER,
    "CertificatePem" TEXT,
    "CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT "FK_AcmeOrders_AcmeAccounts" FOREIGN KEY ("AccountId") REFERENCES "AcmeAccounts" ("AccountId") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "IX_AcmeOrders_OrderId" ON "AcmeOrders" ("OrderId");
CREATE INDEX IF NOT EXISTS "IX_AcmeOrders_AccountId" ON "AcmeOrders" ("AccountId");

-- ACME Authorizations (per identifier in an order)
CREATE TABLE IF NOT EXISTS "AcmeAuthorizations" (
    "Id" SERIAL PRIMARY KEY,
    "AuthId" TEXT NOT NULL UNIQUE,
    "OrderId" TEXT NOT NULL,
    "IdentifierType" TEXT NOT NULL,
    "IdentifierValue" TEXT NOT NULL,
    "Status" TEXT NOT NULL,
    "Expires" TIMESTAMPTZ NOT NULL,
    "CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT "FK_AcmeAuthorizations_AcmeOrders" FOREIGN KEY ("OrderId") REFERENCES "AcmeOrders" ("OrderId") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "IX_AcmeAuthorizations_AuthId" ON "AcmeAuthorizations" ("AuthId");

-- ACME Challenges (HTTP-01, etc.)
CREATE TABLE IF NOT EXISTS "AcmeChallenges" (
    "Id" SERIAL PRIMARY KEY,
    "ChallengeId" TEXT NOT NULL UNIQUE,
    "AuthId" TEXT NOT NULL,
    "Type" TEXT NOT NULL,
    "Token" TEXT NOT NULL,
    "KeyAuthorization" TEXT NOT NULL,
    "Status" TEXT NOT NULL DEFAULT 'pending',
    "ValidatedAt" TIMESTAMPTZ,
    "CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT "FK_AcmeChallenges_AcmeAuthorizations" FOREIGN KEY ("AuthId") REFERENCES "AcmeAuthorizations" ("AuthId") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "IX_AcmeChallenges_ChallengeId" ON "AcmeChallenges" ("ChallengeId");

-- Nonces for replay protection
CREATE TABLE IF NOT EXISTS "AcmeNonces" (
    "Nonce" TEXT PRIMARY KEY,
    "ExpiresAt" TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS "IX_AcmeNonces_ExpiresAt" ON "AcmeNonces" ("ExpiresAt");
