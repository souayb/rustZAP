# Deliberately relay-vulnerable Samba AD domain controller — LAB ONLY.
# Serves LDAP (389/636) + DNS (53); LDAP signing is intentionally NOT required
# and a ghost SPN is seeded, so `rustzap ad` has something real to detect.
FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      samba samba-common-bin samba-dsdb-modules samba-vfs-modules samba-ad-provision \
      winbind ldb-tools dnsutils krb5-user procps iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /entrypoint.sh
COPY ntlm_responder.py /ntlm_responder.py
RUN chmod +x /entrypoint.sh
EXPOSE 389 636 53 5985
ENTRYPOINT ["/entrypoint.sh"]
