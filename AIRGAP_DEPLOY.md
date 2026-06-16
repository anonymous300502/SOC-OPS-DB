# Air-Gapped Deployment

Build the whole stack **once** on a machine with internet, ship a single file,
and deploy on any offline/air-gapped Ubuntu host — no Docker Hub, no package
mirrors, no builds on the target.

## What ships in the bundle

| Image | Purpose |
|-------|---------|
| `postgres:15-alpine` | database (runtime) |
| `soc-ops-db/backend:<version>` | FastAPI backend (pre-built) |
| `soc-ops-db/frontend:<version>` | React app served by nginx (pre-built) |

The backend's `python:3.11-slim` base, the frontend's `node:18-alpine` build
stage, and `nginx:alpine` are all **baked into the saved images** — the target
never needs them.

## One prerequisite on the target

The air-gapped host must already have **Docker Engine + Compose v2**. Installing
Docker itself offline is separate from this bundle — on a Debian/Ubuntu target,
download the `docker-ce`, `docker-ce-cli`, `containerd.io`, and
`docker-compose-plugin` `.deb` files on a connected machine and `dpkg -i` them
on the target. Verify with `docker compose version`.

## Step 1 — Build the bundle (connected machine)

```bash
sudo ./deploy/build-airgap-bundle.sh
# or bump the version:
sudo APP_VERSION=1.1 ./deploy/build-airgap-bundle.sh
```

Produces `socdb-airgap-<version>.tar.gz` in the repo root and prints its size +
SHA-256.

## Step 2 — Transfer

```bash
scp socdb-airgap-1.0.tar.gz user@airgapped-host:~/
# or via USB / approved file-transfer for the secure network
```

## Step 3 — Deploy (air-gapped host)

```bash
tar -xzf socdb-airgap-1.0.tar.gz
cd socdb-airgap-1.0
cp .env.example .env        # then EDIT .env — set every secret
sudo ./deploy-airgap.sh
```

`deploy-airgap.sh` refuses to start while `.env` still holds `change_me`
placeholders. Generate strong values, e.g.:

```bash
openssl rand -hex 32     # SECRET_KEY
openssl rand -base64 24  # POSTGRES_PASSWORD
```

Then browse to `http://<host>/` (API at `http://<host>:8000`). The super-admin
in `.env` is created on first launch only; log in and create other users.

## Updating to a new version

1. On the connected machine: `sudo APP_VERSION=1.1 ./deploy/build-airgap-bundle.sh`
2. Ship + extract the new bundle on the target.
3. `cp` your existing `.env` into the new bundle dir (keep `APP_VERSION` in sync).
4. `sudo ./deploy-airgap.sh` — Postgres data persists in the `postgres_data` volume.

## Troubleshooting

- **`manifest unknown` / tries to pull** on the target → the loaded image tag
  doesn't match `APP_VERSION` in `.env`. Run `docker images` and make them match.
- **`permission denied … /var/run/docker.sock`** → run with `sudo`, or add your
  user to the `docker` group and re-login.
- **Backend restarts / DB errors** → `sudo docker compose logs backend`; usually
  a missing/placeholder value in `.env`.
- **Verify offline behavior** → after `docker load`, the deploy does *not* touch
  any registry; `docker compose up` only uses local images.
