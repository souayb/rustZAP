#!/bin/bash
set -e
REALM="CORP.LOCAL"
DOMAIN="CORP"
ADMINPASS="Passw0rd!"

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  echo "[lab] provisioning Samba AD DC ${REALM} ..."
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --server-role=dc --use-rfc2307 \
    --domain="${DOMAIN}" --realm="${REALM}" \
    --adminpass="${ADMINPASS}" \
    --dns-backend=SAMBA_INTERNAL

  # DELIBERATELY WEAK: accept unsigned simple binds over cleartext LDAP.
  # This is exactly the "LDAP signing not required" relay condition.
  if ! grep -q "ldap server require strong auth" /etc/samba/smb.conf; then
    sed -i '/\[global\]/a\	ldap server require strong auth = no' /etc/samba/smb.conf
  fi

  echo "[lab] seeding a ghost SPN (host with no DNS record) ..."
  samba-tool computer create GHOSTSRV || true
  samba-tool spn add "MSSQLSvc/ghost-db.corp.local:1433" 'GHOSTSRV$' || true
fi

echo "[lab] starting mock WinRM NTLM responder on :5985 ..."
python3 /ntlm_responder.py &
echo "[lab] starting samba (AD DC) ..."
exec samba -i -s /etc/samba/smb.conf
