#!/bin/sh
# Encrypted backup restore evidence: the archive is only readable after decryption.
set -eu
gpg --decrypt /backups/app.sql.gpg | psql -h db -U app app
age -d -i /etc/backup/age.key /backups/uploads.tgz.age | tar xzf - -C /srv/app
