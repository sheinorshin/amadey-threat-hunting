# 1. Deploying MISP

> **Syllabus task (Week 3):** *Deploy MISP and import IOCs.* Recommended reading: MISP Training Documentation.

**MISP** (Malware Information Sharing Platform) stores threat intel as **events** (one incident/campaign) made of **attributes** (IOCs) and **objects**, adds context with **taxonomies** (tags like `tlp:clear`) and **galaxies** (ATT&CK, Malpedia), and automatically **correlates** identical values across events and feeds.

## 1.1 Deployment option used: official `misp-docker`

| Requirement | Value |
|---|---|
| Software | Docker Engine 25+ / Docker Desktop, Compose 2.17+ |
| Images | `ghcr.io/misp/misp-docker/*` (misp-core, misp-nginx, misp-modules) + MariaDB 10.11 + Valkey 7.2 (Redis) + SMTP relay; `misp-guard` is optional (compose profile, not used) |
| RAM | ≈ 3–4 GB free. Deployed on my **16 GB desktop PC** (Windows 11, Docker Desktop 4.93, WSL2 backend, ≈ 7.5 GB given to Docker) — idle MISP stack uses **≈ 1.7 GB** |
| Disk | ≈ 6–7 GB for images + DB (Docker Desktop reported 7.1 GB used) |
| Version deployed | **MISP 2.5.48**, `misp-docker` commit `96e164e`, images `:latest` pulled 2026-10-03 |

### Steps (Windows host with Docker Desktop)

Automated in [`misp/setup-misp.ps1`](misp/setup-misp.ps1) (`powershell -ExecutionPolicy Bypass -File setup-misp.ps1`). Manual equivalent:

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
# merge the values from this repo: week-03-data-processing/misp/env.example  -> .env
#   BASE_URL=https://localhost:8443, NGINX ports 8080/8443, ADMIN_ORG, TZ
cp <this-repo>/week-03-data-processing/misp/docker-compose.override.yml .   # Windows fix, see 1.5
mkdir -p ssl && openssl req -x509 -subj '/CN=localhost' -nodes -newkey rsa:4096 \
  -keyout ssl/key.pem -out ssl/cert.pem -days 365 \
  -addext "subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1"   # misp-nginx needs a cert for https
docker compose pull
docker compose up -d
docker compose ps            # wait until misp-core is "healthy" (first start took ~8 min on Windows)
docker compose logs misp-core | grep -i "MISP is now live"
```

Open **https://localhost:8443** → accept the self-signed certificate → log in.

Default credentials of the image are `admin@admin.test` / `admin` unless `ADMIN_EMAIL`/`ADMIN_PASSWORD` were set — **change the password at first login**.

## 1.2 Post-install configuration

| # | Where (MISP UI) | Action | Why |
|---|---|---|---|
| 1 | *Administration → Server Settings → MISP* | Check `MISP.baseurl` = `https://localhost:8443`, set `MISP.org` | Correct links + org ownership |
| 2 | *Administration → Add Organisation* | Create `AITU-CS2427` (if not set via `.env`) | Event creator org |
| 3 | *Sync Actions → Feeds → Load default feed metadata* (107 feeds) | **Done:** Feodo IP Blocklist enabled + cached; URLhaus (recent CSV), MalwareBazaar (recent MD5), ThreatFox (recent CSV) **cache-only** → *Cache all feeds*. **Not** enabled: CIRCL OSINT (1,681 events) and ThreatFox MISP feed (2,006 daily events) | Cached feeds give *feed hits* for correlation without importing anything. The default scheduled task *Daily fetch of all Feeds* would import every **enabled** MISP feed as thousands of events, which is too much for a lab |
| 4 | *Event Actions → List Taxonomies* (183 loaded) | **Done:** `tlp` and `admiralty-scale` enabled | Tags used by the Amadey events |
| 5 | *Galaxies → List Galaxies* | Already loaded by the first-start scheduled task *Daily update of Galaxies*; `mitre-attack-pattern`, `mitre-malware`, `malpedia` clusters resolved on import | ATT&CK + family context |
| 6 | *Administration → List Auth Keys → Add* | Create an API key for user `admin` (not needed yet — all imports were done in the UI) | Needed for `push_to_misp.py` and the Elastic MISP integration (Week 4+) |
| 7 | *Administration → Scheduled Tasks* | misp-docker creates 9 daily tasks (fetch/cache feeds, pull/push servers, update galaxies/taxonomies/warninglists/noticelists/object templates) | Cache task keeps feed correlation fresh; fetch task only touches *enabled* feeds |

## 1.3 Verification checklist (screenshots → `evidence/`)

- [x] All containers running — [`01_docker_misp-stack_all-running.jpg`](evidence/misp/01_docker_misp-stack_all-running.jpg), log *MISP is now live* — [`02_…`](evidence/misp/02_misp-core_log_misp-is-live_2.5.48.jpg)
- [x] MISP UI with version visible (*Powered by MISP 2.5.48* in every screenshot footer)
- [x] Feeds list with enabled + cached feeds — [`11_feeds_abuse-ch_cached.jpg`](evidence/misp/11_feeds_abuse-ch_cached.jpg)
- [x] Taxonomies `tlp` and `admiralty-scale` enabled — [`12_taxonomies_tlp-admiralty_enabled.jpg`](evidence/misp/12_taxonomies_tlp-admiralty_enabled.jpg)
- [ ] Auth key — postponed until the Elastic MISP integration (Week 4+); blur it in screenshots

All screenshots: [`evidence/`](evidence/).

## 1.4 Troubleshooting

| Symptom | Fix |
|---|---|
| Docker Desktop: *Virtualization support not detected* | Enable **Intel VT-x** in the BIOS (Gigabyte Z390: *Tweaker → Advanced CPU Settings → Intel Virtualization Technology*), keep WSL2 up to date |
| `dependency failed to start: container misp-docker-misp-core-1 is unhealthy`, `misp-nginx` stays *Created* | First start is slower than the 60 s healthcheck grace period → [`docker-compose.override.yml`](misp/docker-compose.override.yml) (`start_period: 900s`); after *MISP is now live* start nginx with `docker compose up -d` |
| `misp-nginx` restart loop: *BASE_URL starts with https://, but SSL certificate is NOT present* | Since misp-docker PR #430 nginx is a separate container that needs `ssl/cert.pem` + `ssl/key.pem` → create a self-signed cert (command in 1.1) |
| `misp-core` restarts in a loop | Not enough RAM → stop other VMs; check `docker compose logs misp-core` |
| Port 80/443 already in use | Already moved to 8080/8443 via `NGINX_HTTP_PORT/NGINX_HTTPS_PORT` |
| Links in MISP point to `localhost` without port | `BASE_URL` wrong → fix in `.env`, `docker compose up -d` again |
| PyMISP `SSLError` | Self-signed cert → `push_to_misp.py` uses `ssl=False` by default (lab only) |

## 1.5 Deployment log — what actually happened (2026-10-03, Asia/Almaty)

| Time | Event |
|---|---|
| — | Docker Desktop refused to start: *Virtualization support not detected* → VT-x enabled in BIOS, WSL2 updated |
| 03:58 | `docker compose up -d` → `db`, `redis`, `misp-modules`, `mail` healthy; `misp-core` started |
| ~03:59 | `misp-core` marked **unhealthy** after 60 s + 3 failed checks → Compose aborted, `misp-nginx` never started |
| 03:59 | Meanwhile `misp-core` kept initialising: copied the MISP data files (galaxies, taxonomies, warninglists, objects) into `./files` (`INIT` marker written) |
| 04:05 | `configure_misp.sh` finished (DB schema, settings, scheduled tasks) → log: *MISP is now live. Users can now log in.* → PHP-FPM started → container **healthy** |
| 04:09 | Started `misp-nginx` → restart loop: *SSL certificate is NOT present* |
| 04:10 | Generated a self-signed certificate in `./ssl` → nginx: *Configuration complete; ready for start up* → UI on **https://localhost:8443** |

**Root cause of the unhealthy container:** the healthcheck only tests whether PHP-FPM listens on port 9002, and PHP-FPM starts *after* the whole initialisation: copying the data files into `./files` (≈ 1 min) and then `configure_misp.sh` (≈ 6 min: database schema, dozens of settings applied one by one through the CakePHP CLI, default scheduled tasks). Total ≈ 8 min on this PC, but Compose only waits 60 s + 3 checks. On Windows, `./files`, `./configs` and `./logs` are bind mounts served through Docker Desktop file sharing, which makes these many small file operations slower than on a Linux host. The container was never broken — Compose just stopped waiting. A longer `start_period` keeps the check honest (healthy as soon as port 9002 answers) while giving the first start enough time.

**Lesson for the defense:** read the container logs before changing anything — the log showed the init was progressing normally, so the fix was configuration (grace period + certificate), not a reinstall.
