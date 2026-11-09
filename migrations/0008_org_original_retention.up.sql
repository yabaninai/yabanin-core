-- NULL means inherit the platform default (processed-only).
ALTER TABLE organizations
    ADD COLUMN retain_original_text boolean;
