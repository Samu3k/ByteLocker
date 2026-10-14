#!/bin/sh
# Host-only orchestration. The snapshot helper sees only /data, without network.
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[ "$(id -u)" = 0 ] || { echo 'Esegui con sudo.' >&2; exit 1; }
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
backup_dir=/DATA/Backups/bytelocker
[ "$#" = 0 ] || { echo 'Questo script non accetta argomenti.' >&2; exit 1; }
[ ! -L /DATA/Backups ] && [ ! -L "$backup_dir" ] || exit 1
mkdir -p -- "$backup_dir"
backup_dir=$(CDPATH= cd -- "$backup_dir" && pwd -P)
case "$backup_dir/" in "$project/"*) echo 'La cartella backup deve stare fuori dal progetto.' >&2; exit 1;; esac
chmod 700 -- "$backup_dir"
lock_dir=/run/bytelocker-maintenance
[ ! -L "$lock_dir" ] || exit 1
mkdir -p -- "$lock_dir"
chmod 700 -- "$lock_dir"
[ ! -L "$lock_dir/backup.lock" ] || exit 1
exec 9> "$lock_dir/backup.lock"
flock -n 9 || { echo 'Un backup è già in corso.' >&2; exit 1; }
tool="$project/maintenance/bytelocker-maintenance"
[ -x "$tool" ] || { echo 'Strumento di backup mancante.' >&2; exit 1; }
container=$(docker compose --project-directory "$project" -f "$project/compose.yaml" ps -q bytelocker)
[ -n "$container" ] || { echo 'ByteLocker deve essere già avviato.' >&2; exit 1; }
[ "$(docker inspect -f '{{.State.Running}}' "$container")" = true ] || exit 1
data_mount=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$container")
[ "$data_mount" = "$project/data" ] || { echo 'Percorso dati personalizzato: adatta prima la procedura di backup.' >&2; exit 1; }
secret_mount=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/secrets/gmail-app-password"}}{{.Source}}{{end}}{{end}}' "$container")
[ -z "$secret_mount" ] || [ "$secret_mount" = "$project/secrets/gmail-app-password" ] || { echo 'Percorso Gmail personalizzato: adatta prima la procedura.' >&2; exit 1; }
image=$(docker inspect -f '{{.Image}}' "$container")
snapshot_name=".bytelocker-snapshot-$(date -u +%Y%m%dT%H%M%SZ)-$$"
snapshot="$project/data/$snapshot_name"
snapshot_created=0
[ ! -e "$snapshot" ] && [ ! -L "$snapshot" ] || exit 1
cleanup() {
 result=$?
 trap - EXIT HUP INT TERM
 # Remove only known snapshot files in the exact directory created for this run.
 if [ "$snapshot_created" = 1 ] && [ -d "$snapshot" ] && [ ! -L "$snapshot" ]; then
  rm -f -- "$snapshot/passwordmanager.db" "$snapshot/passwordmanager.db-wal" "$snapshot/passwordmanager.db-shm" "$snapshot/instance.keys"
  rmdir -- "$snapshot" || { echo 'Pulizia snapshot non riuscita.' >&2; result=1; }
 fi
 exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
docker run --rm --pull never --network none --read-only --user 10001:10001 \
 --cap-drop ALL --security-opt no-new-privileges:true --memory 128m --cpus 0.5 --pids-limit 64 \
 --env GOMEMLIMIT=64MiB --env GOMAXPROCS=1 --env TMPDIR=/tmp \
 --tmpfs /tmp:rw,noexec,nosuid,size=32m,mode=1777 \
 --mount "type=bind,source=$tool,target=/maintenance,readonly" \
 --mount "type=bind,source=$project/data,target=/data" \
 --entrypoint /maintenance "$image" snapshot -data-dir /data -destination "/data/$snapshot_name"
snapshot_created=1
archive="$backup_dir/bytelocker-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
"$tool" backup -root "$project" -out "$archive" -snapshot "$snapshot"
"$tool" verify -archive "$archive"
sha256sum -- "$archive" > "$archive.sha256"
[ "$(docker inspect -f '{{.State.Health.Status}}' "$container")" = healthy ] || { echo 'Backup verificato, ma il server non risulta healthy: controlla CasaOS.' >&2; exit 1; }
echo "Backup verificato: $archive"
echo 'Copia anche il backup su un disco separato. Contiene segreti del server: non condividerlo.'
