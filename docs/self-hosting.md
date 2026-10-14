# Host your own server

[Italiano](it/self-hosting.md) · [Server download](https://github.com/Samu3k/ByteLocker/releases/tag/v0.3.1)

Each instance has independent accounts, keys and data. These steps target CasaOS / Linux x86_64 with Docker Compose. The bundled maintenance executable is x86_64; ARM64 requires rebuilding it from source.

## 1. Prepare

Extract the server package into /DATA/AppData/bytelocker, without an extra nested folder. For a **new installation only**:

```sh
cd /DATA/AppData/bytelocker
docker --version
docker compose version
if [ -e data ] || [ -L data ]; then
  echo "Existing data: stop and follow the update guide."
else
  sudo mkdir data
  sudo chown 10001:10001 data
  sudo chmod 700 data
fi
```

Preserve existing data, secrets and .env during updates. Keep the database and instance.keys together.

## 2. Configure Gmail

```sh
test -e .env || cp .env.example .env
sudo chmod 600 .env
sudo mkdir -p secrets
sudo chmod 700 secrets
sudo nano .env
```

Set PM_SMTP_USERNAME to your own Gmail address in .env. Create a [Google app password](https://support.google.com/accounts/answer/185833), then put only that password in the following file. Do not paste it into a shell command or Git.

```sh
sudo nano secrets/gmail-app-password
sudo chown 10001:10001 secrets/gmail-app-password
sudo chmod 600 secrets/gmail-app-password
```

## 3. Build and start

```sh
sudo docker compose build bytelocker
sudo docker compose -f compose.yaml -f compose.gmail.yaml up -d bytelocker
sudo docker compose -f compose.yaml -f compose.gmail.yaml ps
sudo docker compose logs --tail=30 bytelocker
```

Wait for healthy status and enabled email/registration. Resolve email errors before registering. The default Compose publishes no host ports.

## 4. Connect over HTTPS

For a temporary test tunnel:

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml up -d
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --tail=100 cloudflared
```

Use the HTTPS origin printed in the logs for clients, and append /admin for administration. No extra VPN app is needed. Keep your instance URL out of Git. Quick Tunnels can change address and have no uptime guarantee; prepare a stable HTTPS origin before regular use. [Cloudflare documentation](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

## 5. Create accounts

Create the first administrator invitation on a new instance:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data bootstrap
```

Use the returned invitation_secret in a client and complete email verification. Bootstrap closes after the first administrator activates. Generate a 24-hour panel key:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data panel-key
```

Enter admin_panel_key at /admin. Create email-bound invitations and manage user accounts there. Administrators are protected from deletion; the panel cannot view vault contents. Alternatively:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data invite -email friend@example.com -ttl 24h
```

Share each user's invitation privately, never your panel key.

## 6. Back up

```sh
sudo chmod 755 maintenance/bytelocker-maintenance
sudo sh maintenance/backup.sh
```

After a verified backup, test restoration into a separate new directory. With cron active, enable daily backups at 03:30 in the server timezone:

```sh
sudo sh maintenance/install-daily.sh
```

Backup archives include operational secrets and are not encrypted as a whole. Keep them private and store a protected copy separately. Detailed [backup](backup-casaos.md) and [update](update-0.3.1.md) procedures are currently in Italian.
