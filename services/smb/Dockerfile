FROM ubuntu:22.04
# samba-vfs-modules is NOT pulled in by --no-install-recommends, but it's
# where full_audit.so (smb.conf: vfs objects = full_audit) actually lives.
# Without it, smbd_vfs_init fails for every share including IPC$ itself -
# meaning no client can connect at all, not just that audit logging is
# missing (found via a real failed connection: NT_STATUS_BAD_NETWORK_NAME
# on the very first smbclient test of this deployment).
RUN apt-get update && apt-get install -y --no-install-recommends \
    samba \
    samba-vfs-modules \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*
RUN install -d -m 0755 /srv/samba/Operations /srv/samba/Backups /srv/samba/Docs
COPY bait_files/ /srv/samba/
RUN chown -R nobody:nogroup /srv/samba && chmod -R 0755 /srv/samba
COPY config/smb.conf /etc/samba/smb.conf
COPY config/rsyslog-full-audit.conf /etc/rsyslog.d/60-full-audit.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 139 445
CMD ["/entrypoint.sh"]
