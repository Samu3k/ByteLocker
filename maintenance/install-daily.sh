#!/bin/sh
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[ "$(id -u)" = 0 ] || { echo 'Esegui con sudo.' >&2; exit 1; }
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ "$project" = /DATA/AppData/bytelocker ] || { echo 'Per questa installazione è richiesto /DATA/AppData/bytelocker.' >&2; exit 1; }
[ -x "$project/maintenance/bytelocker-maintenance" ] || exit 1
command -v flock >/dev/null
command -v docker >/dev/null
command -v sha256sum >/dev/null
[ -d /etc/cron.d ] || { echo 'Cron non disponibile: configura un timer sul server.' >&2; exit 1; }
if command -v systemctl >/dev/null; then
 systemctl is-active --quiet cron || systemctl is-active --quiet crond || { echo 'Attiva il servizio cron prima di installare la pianificazione.' >&2; exit 1; }
fi
# Refuse a foreign schedule; repeat installation is safe and changes no others.
cron_file=/etc/cron.d/bytelocker-backup
if [ -e "$cron_file" ]; then
 grep -q '^# ByteLocker backup schedule v1$' "$cron_file" || { echo 'File cron già presente e non riconosciuto.' >&2; exit 1; }
fi
[ ! -L /DATA/Backups ] && [ ! -L /DATA/Backups/bytelocker ] && [ ! -L /var/log/bytelocker-backup.log ] && [ ! -L "$cron_file" ] || exit 1
mkdir -p /DATA/Backups/bytelocker
chmod 700 /DATA/Backups/bytelocker
touch /var/log/bytelocker-backup.log
chmod 600 /var/log/bytelocker-backup.log
stage=$(mktemp /etc/cron.d/.bytelocker-backup.XXXXXX)
trap 'rm -f -- "$stage"' EXIT HUP INT TERM
cat > "$stage" <<'CRON'
# ByteLocker backup schedule v1
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 3 * * * root /bin/sh /DATA/AppData/bytelocker/maintenance/backup.sh >> /var/log/bytelocker-backup.log 2>&1
CRON
chown root:root "$stage"
chmod 644 "$stage"
mv -f -- "$stage" "$cron_file"
echo 'Backup giornaliero configurato alle 03:30, secondo il fuso orario del server.'
echo 'Verifica che il servizio cron sia attivo. I backup non vengono cancellati automaticamente.'
