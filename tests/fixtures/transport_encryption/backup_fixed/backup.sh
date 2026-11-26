#!/bin/sh
# Fixed fixture: every dump/archive is encrypted before it leaves the host.
set -eu
pg_dump -h db -U app app | gpg --encrypt --recipient backup@example.com > /backups/app.sql.gpg
tar czf - /srv/app/uploads | age -r age1fixturerecipient > /backups/uploads.tgz.age
aws s3 cp /backups s3://example-backups/ --recursive --sse aws:kms
