Aegis
Supply-chain risk tracker that connects SBOM/SCA scanning with real-time threat intelligence to generate repo-specific vulnerability alerts.

What It Does
Aegis runs two pipelines — SBOM/SCA and News Ingestion — connected by a Match Engine that turns generic threat intel into actionable, repo-specific alerts. A RAG-powered chatbot lets you ask natural-language questions about your supply chain security posture.

Pipeline Overview

Key Features
SBOM Scanning: Discovers dependencies via Cartograph, scans for vulnerabilities via Sentinel, resolves licenses via a 4-tier pipeline (pattern rules, deps.dev, GitHub, manual)
News Ingestion: Monitors 22 security feeds (Socket.dev, Snyk, CISA, NVD, etc.), filters by relevance, deduplicates with fuzzy + LLM matching, enriches via Gemini
Match Engine: Cross-references news articles against your SBOM inventory, identifies vulnerable repos with semver comparison
Validator: Spawns ECS Fargate tasks for reachability analysis — confirms if vulnerable code paths are actually exercised
Ask Aegis (RAG Chatbot): Natural-language Q&A about your supply chain — retrieves from SBOM, news, match results, and remediation guides
Remediation Engine: Generates prioritized fix steps with per-repo commands when vulnerabilities are found
Web Dashboard: Real-time overview of components, vulnerabilities, news feed, match results, and interactive chatbot
Quick Start (Demo Mode)
Demo mode runs the full pipeline with mock data — no API keys, database, or external tools required.

# Clone and install
git clone https://github.com/SachinArora756/aegis.git
cd aegis
pip install -e .

# Run the web dashboard (demo mode)
aegis web --demo --port 3000

# Open http://localhost:3000 in your browser
Demo CLI Commands
# Full pipeline demo in terminal
aegis demo full

# Individual stages
aegis demo sbom
aegis demo news
aegis demo match

# RAG chatbot demo
aegis demo chat

# Interactive chat session
aegis rag chat --demo
Production Setup (Step by Step)
Prerequisites
Python 3.11+ — python.org/downloads
Docker Desktop — docker.com/products/docker-desktop (for PostgreSQL)
Git — git-scm.com
Step 1: Clone and Install
git clone https://github.com/SachinArora756/aegis.git
cd aegis
pip install -e .
Step 2: Install Scanning Tools
Aegis uses three open-source scanning tools. Install them via winget (Windows), brew (macOS/Linux), or download from GitHub:

Windows:

winget install Anchore.Syft
winget install Anchore.Grype
winget install AquaSecurity.Trivy
macOS / Linux:

brew install syft grype trivy
Restart your terminal after installing so the tools are available on PATH.

Step 3: Get a Free Gemini API Key
Go to aistudio.google.com/apikey
Sign in with your Google account
Click "Create API Key" — it's free (15 requests/minute)
Copy the key
Step 4: Configure Environment
Create a .env file in the project root:

# .env
GEMINI_API_KEY=your-gemini-api-key-here
LLM_PROVIDER=gemini
DATABASE_URL=postgresql+asyncpg://aegis:aegis_dev@localhost:5432/aegis_db
Note: If port 5432 is already in use by another PostgreSQL instance, change the port in both .env and docker-compose.yml (e.g., use 5433).

All environment variables:

Variable	Purpose	Required
GEMINI_API_KEY	Google Gemini for LLM + embeddings + chat	Yes (free)
LLM_PROVIDER	LLM backend (gemini or anthropic)	No (defaults to gemini)
DATABASE_URL	PostgreSQL connection string	Yes
SLACK_BOT_TOKEN	Slack alerts	No (optional)
SLACK_CHANNEL_ID	Target Slack channel	No (optional)
Step 5: Start PostgreSQL
Make sure Docker Desktop is running, then:

docker compose up -d
This starts a PostgreSQL 16 container with the pgvector extension pre-installed.

Step 6: Initialize the Database
aegis init-db
This creates all the required tables (SBOM inventory, news articles, match results, embeddings, chat sessions, etc.).

Step 7: Run the Pipelines
# Scan a repository for dependencies and vulnerabilities
aegis sbom scan ./path/to/repo

# Scan the aegis project itself as a test
aegis sbom scan .

# Fetch and enrich security news from 22 RSS feeds
aegis news run

# Cross-reference a news article against your SBOM inventory
aegis match <news_id>

# Index the knowledge base for RAG chatbot
aegis rag index

# Start an interactive chat session in terminal
aegis rag chat
Step 8: Launch the Web Dashboard
aegis web --port 3000
Open http://localhost:3000 in your browser. The dashboard shows data from your database — SBOM inventory, news feed, match results, and the Ask Aegis chatbot.

Continuous Monitoring
To keep the news feed updated automatically:

# Poll feeds every 30 minutes
aegis news watch --interval 30
All CLI Commands
aegis sbom scan <path>        Scan a repo (Cartograph + Auditor + Fuse + Sentinel + Licenser)
aegis news run                Fetch + filter + enrich security articles
aegis news watch --interval N Continuous news polling (minutes)
aegis match <news_id>         Cross-reference news against SBOM inventory
aegis rag index               Index knowledge base for RAG
aegis rag chat                Interactive chat in terminal
aegis web --port 3000         Start web dashboard
aegis init-db                 Create database tables
aegis demo full               Run full pipeline with mock data (no setup needed)
aegis demo chat               Demo the RAG chatbot
aegis web --demo --port 3000  Web dashboard with mock data (no setup needed)
Project Structure
aegis/
  cli.py              CLI entry point (Click)
  config.py           Pydantic Settings (env-based config)
  db/
    engine.py          Async SQLAlchemy engine
    models.py          ORM models (8 tables)
  sbom/
    scanner.py         SBOM/SCA pipeline orchestrator
    cartograph.py      SBOM generation
    auditor.py         License scanning
    fuse.py            PURL-based SBOM merge
    sentinel.py        Vulnerability scanning
    licenser.py        4-tier license resolution
  news/
    agent.py           News ingestion orchestrator
    fetcher.py         RSS + API fetcher (22 sources)
    filter.py          Keyword relevance filter
    dedup.py           3-phase deduplication
    enricher.py        LLM-based classification
  match/
    engine.py          SBOM x News cross-reference
  validator/
    dispatcher.py      ECS Fargate task spawner
  notify/
    slack.py           Slack alert formatting
  rag/
    embedder.py        Text embedding (Gemini / mock)
    store.py           Vector store (pgvector / in-memory)
    retriever.py       Context retrieval
    chat.py            Chat engine (Gemini / mock)
    remediation.py     Fix recommendation engine
    knowledge.py       Static remediation guides
    ingest.py          Data indexing pipeline
  demo/
    runner.py          CLI demo runner
    data.py            Mock SBOM, news, match data
    rag_data.py        Mock chat, incidents, remediation data
  web/
    app.py             FastAPI application factory
    routes/            Route modules (dashboard, sbom, news, match, chat, demo)
    templates/         Jinja2 HTML templates
    static/            JS + CSS assets
Web Dashboard Pages
Page	URL	Description
Dashboard	/	Overview stats, severity breakdown, recent activity
SBOM Inventory	/sbom	Component browser, vulnerability list, scan results
News Feed	/news	Enriched security articles with classification
Match Results	/match	Cross-reference results grouped by incident
Ask Aegis	/chat	RAG-powered security chatbot
Live Demo	/demo	Interactive pipeline visualization with streaming
Tech Stack
Backend: Python 3.11+, FastAPI, SQLAlchemy (async), Click
Database: PostgreSQL 16 + pgvector
AI/ML: Google Gemini (LLM + embeddings + chat, free tier)
Frontend: Jinja2, Tailwind CSS, vanilla JS, WebSocket streaming
Scanning: Cartograph (SBOM), Auditor (licenses), Sentinel (vulnerabilities)
Alerts: Slack Bot API
Infra: Docker Compose, AWS ECS Fargate (validator)
License
MIT
