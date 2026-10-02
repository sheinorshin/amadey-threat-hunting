# 1. Deploying MISP

> **Syllabus task (Week 3):** *Deploy MISP and import IOCs.* Recommended reading: MISP Training Documentation.

**MISP** (Malware Information Sharing Platform) stores threat intel as **events** (one incident/campaign) made of **attributes** (IOCs) and **objects**, adds context with **taxonomies** (tags like `tlp:clear`) and **galaxies** (ATT&CK, Malpedia), and automatically **correlates** identical values across events and feeds.

## 1.1 Deployment option used: official `misp-docker`

| Requirement | Value |
|---|---|
| Software | Docker Engine 25+ / Docker Desktop, Compose 2.17+ |
| Images | `ghcr.io/misp/misp-docker/*` (core, nginx, modules, guard) + MariaDB + Redis |
| RAM | ≈ 3–4 GB free. On my 8 GB laptop: **stop Elasticsearch/Kibana VMs while MISP runs**, or run MISP inside the CentOS VM only when ES is down |
| Disk | ≈ 6 GB for images + DB |

### Steps (Windows host with Docker Desktop, or the CentOS VM)

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
# merge the values from this repo: week-03-data-processing/misp/env.example  -> .env
#   BASE_URL=https://localhost:8443, NGINX ports 8080/8443, ADMIN_ORG, ADMIN_PASSWORD, TZ
docker compose pull
docker compose up -d
docker compose ps            # wait until misp-core is "healthy" (first start takes 3-5 min)
docker compose logs -f misp-core | grep -i "MISP is ready"   # optional
```

Open **https://localhost:8443** → accept the self-signed certificate → log in.

Default credentials of the image are `admin@admin.test` / `admin` unless `ADMIN_EMAIL`/`ADMIN_PASSWORD` were set — **change the password at first login**.

## 1.2 Post-install configuration

| # | Where (MISP UI) | Action | Why |
|---|---|---|---|
| 1 | *Administration → Server Settings → MISP* | Check `MISP.baseurl` = `https://localhost:8443`, set `MISP.org` | Correct links + org ownership |
| 2 | *Administration → Add Organisation* | Create `AITU-CS2427` (if not set via `.env`) | Event creator org |
| 3 | *Sync Actions → Feeds → Load default feed metadata* | Enable **CIRCL OSINT Feed**, **abuse.ch ThreatFox**, **URLhaus**, **MalwareBazaar** (if listed) → *Fetch and store all feed data* | My IOCs get **correlated** against community data |
| 4 | *Event Actions → List Taxonomies* | Enable `tlp`, `admiralty-scale` | Tags used by the Amadey event |
| 5 | *Event Actions → List Galaxies → Update Galaxies* | Ensure `mitre-attack-pattern`, `mitre-malware`, `malpedia` exist | ATT&CK + family context |
| 6 | *Administration → List Auth Keys → Add* | Create an API key for user `admin` | Needed for `push_to_misp.py` and the Elastic MISP integration |
| 7 | *Administration → Scheduled Tasks* | Feed fetch every 24 h | Keep correlation data fresh |

## 1.3 Verification checklist (screenshots → `evidence/`)

- [ ] `docker compose ps` — all containers *running/healthy*
- [ ] MISP dashboard after login (version number visible)
- [ ] Feeds list with at least one enabled + cached feed
- [ ] Taxonomies `tlp` and `admiralty-scale` enabled
- [ ] Auth key created (blur the key!)

## 1.4 Troubleshooting

| Symptom | Fix |
|---|---|
| `misp-core` restarts in a loop | Not enough RAM → stop other VMs; check `docker compose logs misp-core` |
| Port 80/443 already in use | Already moved to 8080/8443 via `NGINX_HTTP_PORT/NGINX_HTTPS_PORT` |
| Links in MISP point to `localhost` without port | `BASE_URL` wrong → fix in `.env`, `docker compose up -d` again |
| PyMISP `SSLError` | Self-signed cert → `push_to_misp.py` uses `ssl=False` by default (lab only) |
