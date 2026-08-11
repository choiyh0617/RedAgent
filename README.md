# PentestFlow

PentestFlow is an MVP autonomous pentest assistant for authorized lab environments only. Phase 5 adds a local-first LLM analysis layer with Ollama, structured prompt boundaries, confidence gating, and deterministic routing around the model.

## Current scope

- FastAPI API with `/health` and initial scan endpoints
- CLI entrypoint: `python -m app.main scan <target>`
- Deterministic scope enforcement for `localhost`, `127.0.0.1`, and user-configured lab ranges
- Safe `network_scan`, enriched `web_probe`, deterministic technology detection, `robots.txt`, and small fixed endpoint discovery
- In-scope crawler with depth/page limits, deduplication, and same-origin enforcement
- Safe Nuclei wrapper with JSONL parsing into structured `FindingCandidate` records
- Local RAG knowledge retrieval attached to finding candidates
- Ollama-backed `AnalysisAgent` with model routing, confidence evaluation, caching, and graceful degradation
- Unit tests for subprocess handling, HTTP parsing, crawler limits, technology evidence, robots, endpoints, Nuclei parsing, RAG retrieval, model routing, injection screening, and partial recon behavior

## Safety model

- No arbitrary public scanning
- No redirect following outside configured scope
- No model-generated shell execution
- No destructive validation
- No autonomous exploit execution from model output

## Quick start

If you just want the shortest path, use this:

```bash
./scripts/pentestflow.sh setup
./scripts/pentestflow.sh demo
```

That is the main entrypoint now.

On macOS you can also double-click:

- `scripts/pentestflow_setup.command`
- `scripts/pentestflow_demo.command`

What changed:

- `setup` creates `.venv`, installs requirements, and copies local env files
- `demo` starts Ollama automatically if it is installed but not running
- `demo` pulls `llama3.2:latest` automatically if it is missing

### Juice Shop demo

Run the full local demo with one command:

```bash
./scripts/pentestflow.sh demo
```

Or double-click `scripts/pentestflow_demo.command` on macOS.

What it does:

- checks `.venv`, Ollama, Docker, and the local model
- starts `bkimminich/juice-shop` on `http://127.0.0.1:3000` if needed
- rebuilds the knowledge base
- runs `PentestFlow` against Juice Shop

### Scan another authorized target

1. Copy the example env file:

```bash
cp .env.authorized-target.example .env.authorized-target
```

2. Edit `PENTESTFLOW_ALLOWED_HOSTS` and `PENTESTFLOW_ALLOWED_NETWORKS` so they only include systems you are explicitly authorized to test.

3. Run the scan:

```bash
./scripts/pentestflow.sh scan http://demo.testfire.net
```

The scan will be blocked if the target is not inside the configured scope.

### One command reference

```bash
./scripts/pentestflow.sh demo
./scripts/pentestflow.sh setup
./scripts/pentestflow.sh scan http://your-authorized-target
./scripts/pentestflow.sh api
./scripts/pentestflow.sh eval
```

### Manual CLI

```bash
.venv/bin/python -m app.main knowledge rebuild
.venv/bin/python -m app.main scan http://127.0.0.1:3000
.venv/bin/python -m app.main eval run --benchmark juice-shop-safe-v1 --profile optimized
```

### API

```bash
.venv/bin/uvicorn app.main:api --host 127.0.0.1 --port 8000
```

## Test

```bash
.venv/bin/python -m unittest discover -s tests -v
```
