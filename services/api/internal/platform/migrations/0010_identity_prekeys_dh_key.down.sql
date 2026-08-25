ALTER TABLE identity_signed_prekeys
    DROP COLUMN IF EXISTS identity_dh_public_key,
    DROP COLUMN IF EXISTS identity_dh_public_key_signature;
