-- Optional per-deployment shape subset (JSON array of UpstreamFormat strings).
-- NULL (the default) means the deployment inherits every shape its provider serves.
ALTER TABLE deployments ADD COLUMN shapes TEXT;
