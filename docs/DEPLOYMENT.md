# ULPF Deployment Guide
**Local and Production Container Deployment**

---

## 1. Local Python Deployment

```bash
# Clone the repository
git clone https://github.com/ntro-sih2026/ulpf.git
cd ulpf

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Launch pipeline and web interface
python run_ulpf.py
```
- Dashboard: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`
- UDP Syslog: `localhost:5140`
- TCP Syslog: `localhost:1514`

---

## 2. Docker Container Deployment

```bash
# Build and start container with Docker Compose
docker-compose up --build -d

# Check container status
docker ps

# Check logs
docker-compose logs -f ulpf-engine
```

---

## 3. Persistent Volumes

| Directory | Purpose |
| :--- | :--- |
| `data/raw_store/` | Immutable write-once raw log storage with SHA-256 integrity files |
| `data/search_index.db` | SIEM search and analytical database (SQLite FTS5) |
| `data/data_lake/` | Partitioned Apache Parquet columnar files for AI/ML |
| `data/parsers/` | Versioned parser definition JSON files |
| `data/onboarding_sessions/` | Active and historical Drain3 template mining sessions |
| `data/error_queue/` | Dead-letter error queue files |
