#!/bin/sh
# Intentionally insecure fixture: plaintext dumps and upload archive shipped off-host.
set -eu
pg_dump "postgres://app:fixturepass@db/app" > /backups/app.sql
mysqldump -uroot -pfixturepass shop > /backups/shop.sql
tar czf /backups/uploads.tgz /srv/app/uploads
aws s3 cp /backups s3://example-backups/ --recursive
