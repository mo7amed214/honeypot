FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    samba \
    && rm -rf /var/lib/apt/lists/*
RUN install -d -m 0755 /srv/samba/Operations /srv/samba/Backups /srv/samba/Docs
COPY bait_files/ /srv/samba/
RUN chown -R nobody:nogroup /srv/samba && chmod -R 0755 /srv/samba
COPY config/smb.conf /etc/samba/smb.conf
EXPOSE 139 445
CMD ["smbd", "--foreground", "--no-process-group"]
