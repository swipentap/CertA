-- CertA Database Schema for CockroachDB/PostgreSQL
-- This script creates all tables without using EF Core migrations

-- Users table (simplified from AspNetUsers)
CREATE TABLE IF NOT EXISTS "Users" (
    "Id" TEXT PRIMARY KEY,
    "UserName" VARCHAR(256) NOT NULL,
    "NormalizedUserName" VARCHAR(256),
    "Email" VARCHAR(256) NOT NULL,
    "NormalizedEmail" VARCHAR(256),
    "EmailConfirmed" BOOLEAN NOT NULL DEFAULT false,
    "PasswordHash" TEXT NOT NULL,
    "SecurityStamp" TEXT,
    "ConcurrencyStamp" TEXT,
    "PhoneNumber" TEXT,
    "PhoneNumberConfirmed" BOOLEAN NOT NULL DEFAULT false,
    "TwoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "LockoutEnd" TIMESTAMPTZ,
    "LockoutEnabled" BOOLEAN NOT NULL DEFAULT false,
    "AccessFailedCount" INTEGER NOT NULL DEFAULT 0,
    "FirstName" TEXT,
    "LastName" TEXT,
    "Organization" TEXT,
    "CreatedDate" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "IsActive" BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS "IX_Users_NormalizedUserName" ON "Users" ("NormalizedUserName");
CREATE INDEX IF NOT EXISTS "IX_Users_NormalizedEmail" ON "Users" ("NormalizedEmail");

-- Roles table
CREATE TABLE IF NOT EXISTS "Roles" (
    "Id" TEXT PRIMARY KEY,
    "Name" VARCHAR(256),
    "NormalizedName" VARCHAR(256),
    "ConcurrencyStamp" TEXT
);

CREATE INDEX IF NOT EXISTS "IX_Roles_NormalizedName" ON "Roles" ("NormalizedName");

-- UserRoles table
CREATE TABLE IF NOT EXISTS "UserRoles" (
    "UserId" TEXT NOT NULL,
    "RoleId" TEXT NOT NULL,
    PRIMARY KEY ("UserId", "RoleId"),
    CONSTRAINT "FK_UserRoles_Users_UserId" FOREIGN KEY ("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_UserRoles_Roles_RoleId" FOREIGN KEY ("RoleId") REFERENCES "Roles" ("Id") ON DELETE CASCADE
);

-- UserClaims table
CREATE TABLE IF NOT EXISTS "UserClaims" (
    "Id" SERIAL PRIMARY KEY,
    "UserId" TEXT NOT NULL,
    "ClaimType" TEXT,
    "ClaimValue" TEXT,
    CONSTRAINT "FK_UserClaims_Users_UserId" FOREIGN KEY ("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "IX_UserClaims_UserId" ON "UserClaims" ("UserId");

-- UserLogins table
CREATE TABLE IF NOT EXISTS "UserLogins" (
    "LoginProvider" TEXT NOT NULL,
    "ProviderKey" TEXT NOT NULL,
    "ProviderDisplayName" TEXT,
    "UserId" TEXT NOT NULL,
    PRIMARY KEY ("LoginProvider", "ProviderKey"),
    CONSTRAINT "FK_UserLogins_Users_UserId" FOREIGN KEY ("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "IX_UserLogins_UserId" ON "UserLogins" ("UserId");

-- UserTokens table
CREATE TABLE IF NOT EXISTS "UserTokens" (
    "UserId" TEXT NOT NULL,
    "LoginProvider" TEXT NOT NULL,
    "Name" TEXT NOT NULL,
    "Value" TEXT,
    PRIMARY KEY ("UserId", "LoginProvider", "Name"),
    CONSTRAINT "FK_UserTokens_Users_UserId" FOREIGN KEY ("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE
);

-- RoleClaims table
CREATE TABLE IF NOT EXISTS "RoleClaims" (
    "Id" SERIAL PRIMARY KEY,
    "RoleId" TEXT NOT NULL,
    "ClaimType" TEXT,
    "ClaimValue" TEXT,
    CONSTRAINT "FK_RoleClaims_Roles_RoleId" FOREIGN KEY ("RoleId") REFERENCES "Roles" ("Id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "IX_RoleClaims_RoleId" ON "RoleClaims" ("RoleId");

-- DataProtectionKeys table
CREATE TABLE IF NOT EXISTS "DataProtectionKeys" (
    "Id" INTEGER PRIMARY KEY,
    "FriendlyName" VARCHAR(255),
    "Xml" TEXT NOT NULL
);

-- CertificateAuthorities table
CREATE TABLE IF NOT EXISTS "CertificateAuthorities" (
    "Id" SERIAL PRIMARY KEY,
    "Name" VARCHAR(255) NOT NULL,
    "CommonName" VARCHAR(255) NOT NULL,
    "Organization" VARCHAR(255) NOT NULL,
    "Country" VARCHAR(2) NOT NULL,
    "State" VARCHAR(255) NOT NULL,
    "Locality" VARCHAR(255) NOT NULL,
    "CertificatePem" TEXT NOT NULL,
    "PrivateKeyPem" TEXT NOT NULL,
    "CreatedDate" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "ExpiryDate" TIMESTAMPTZ NOT NULL,
    "IsActive" BOOLEAN NOT NULL DEFAULT true
);

CREATE UNIQUE INDEX IF NOT EXISTS "IX_CertificateAuthorities_IsActive" ON "CertificateAuthorities" ("IsActive") WHERE "IsActive" = true;

-- Certificates table
CREATE TABLE IF NOT EXISTS "Certificates" (
    "Id" SERIAL PRIMARY KEY,
    "CommonName" VARCHAR(255) NOT NULL,
    "SubjectAlternativeNames" TEXT,
    "SerialNumber" VARCHAR(50) NOT NULL,
    "IssuedDate" TIMESTAMPTZ NOT NULL,
    "ExpiryDate" TIMESTAMPTZ NOT NULL,
    "Status" INTEGER NOT NULL,
    "Type" INTEGER NOT NULL,
    "CertificatePem" TEXT NOT NULL,
    "PublicKeyPem" TEXT NOT NULL,
    "PrivateKeyPem" TEXT NOT NULL,
    "UserId" TEXT NOT NULL,
    CONSTRAINT "FK_Certificates_Users_UserId" FOREIGN KEY ("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS "IX_Certificates_UserId" ON "Certificates" ("UserId");
CREATE INDEX IF NOT EXISTS "IX_Certificates_Status" ON "Certificates" ("Status");
CREATE INDEX IF NOT EXISTS "IX_Certificates_ExpiryDate" ON "Certificates" ("ExpiryDate");

-- Application logs table (for Serilog)
CREATE TABLE IF NOT EXISTS "application_logs" (
    "id" SERIAL PRIMARY KEY,
    "message" TEXT,
    "message_template" TEXT,
    "level" VARCHAR(128),
    "timestamp" TIMESTAMPTZ NOT NULL,
    "exception" TEXT,
    "properties" JSONB,
    "props_test" TEXT,
    "machine_name" VARCHAR(128)
);

CREATE INDEX IF NOT EXISTS "IX_application_logs_timestamp" ON "application_logs" ("timestamp");
CREATE INDEX IF NOT EXISTS "IX_application_logs_level" ON "application_logs" ("level");