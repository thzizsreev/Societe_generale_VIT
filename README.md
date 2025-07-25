# Threat Intelligence Feed Aggregator

**AI-Powered Cybersecurity Threat Monitoring Dashboard**

A comprehensive threat intelligence aggregation platform that consolidates and analyzes cyber threat data from multiple online sources using AI. Built for security teams, detection engineers, and cybersecurity professionals.

## Features

- **Multi-Source Data Collection**: Aggregates from RSS feeds, Reddit, and cybersecurity blogs
- **AI-Powered Analysis**: Uses both local (Ollama) and cloud (Claude) LLMs for threat analysis
- **IOC Extraction**: Automatically extracts Indicators of Compromise (IPs, URLs, hashes, CVEs)
- **Priority Scoring**: AI-based threat prioritization and categorization
- **Web Dashboard**: Intuitive Gradio-based interface for monitoring and analysis
- **Modular Pipeline**: Three-stage processing (Collection → Triage → Final Analysis)

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │    │   AI Analysis   │    │   Dashboard     │
│                 │    │                 │    │                 │
│ • RSS Feeds     │───▶│ • Ollama Triage │───▶│ • Gradio Web UI │
│ • Reddit        │    │ • Claude Final  │    │ • IOC Display   │
│ • Cyber Blogs   │    │ • IOC Extract   │    │ • Threat Scores │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

1. **Python 3.8+**
2. **Ollama** (for local LLM analysis)
3. **OpenRouter API Key** (for Claude analysis)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/thzizsreev/Societe_generale_VIT.git
cd Societe_generale_VIT
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Set up Ollama:**
```bash
# Install Ollama (visit https://ollama.ai for instructions)
# Pull a model
ollama pull llama3.1

# Start Ollama server
ollama serve
```

4. **Configure environment variables:**
```bash
cp .env.template .env
# Edit .env file with your API keys
```

5. **Run the web interface:**
```bash
python main.py
```

Visit `http://localhost:7860` to access the dashboard.

## Usage

### Pipeline Execution

The system follows a three-stage pipeline:

1. **Data Collection (`src/data_collection/collector.py`)**:
   - Fetches articles from RSS feeds and Reddit
   - Scrapes full article content
   - Saves to `data/raw_articles.json`

2. **Triage Analysis (`src/analysis/triage_analyzer.py`)**:
   - Uses Ollama (local LLM) to analyze articles
   - Extracts threat indicators and assigns priority scores
   - Saves to `data/triaged_articles.json`

3. **Final Analysis (`src/analysis/final_analyzer.py`)**:
   - Uses Claude to rewrite high-priority articles
   - Generates professional threat briefings
   - Saves to `docs/final_briefing.md`

### Command Line Usage

```bash
# Run individual components
python main.py --collect    # Data collection
python main.py --analyze    # AI analysis
python main.py --pipeline   # Full pipeline

# Or use the web interface for integrated control
python main.py
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Ollama Configuration (for triage.py)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1

# OpenRouter Configuration (for triage2.py - Claude)
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Reddit API Configuration (optional)
CLIENT_ID=your_reddit_client_id
CLIENT_SECRET=your_reddit_client_secret
USER_AGENT=ThreatIntelAggregator/1.0
```

### Data Sources

The system is configured to collect from:
- **RSS Feeds**: TheHackersNews, BleepingComputer, Threatpost
- **Reddit**: r/cybersecurity, r/cybersecurity_news
- **Configurable**: Easy to add new sources

## Dashboard Features

### Pipeline Control
- One-click pipeline execution
- Individual stage control
- Real-time status monitoring

### Threat Overview
- Article collection statistics
- High-priority threat table
- IOC extraction and display

### Briefing Viewer
- AI-generated threat briefings
- Professional security analysis
- Export capabilities

## Technical Details

### IOC Extraction
Automatically extracts:
- **IP Addresses**: IPv4 patterns
- **URLs**: HTTP/HTTPS links
- **File Hashes**: MD5, SHA1, SHA256
- **Domains**: Suspicious domain names
- **CVEs**: CVE identifiers

### AI Analysis Pipeline
- **Ollama (Triage)**: Fast local analysis for initial scoring
- **Claude (Final)**: High-quality writing for final briefings
- **Structured Output**: JSON-formatted analysis results

### Threat Scoring
Articles are scored 1-10 based on:
- CVE mentions and active exploitation
- Threat actor attribution
- Technical indicators presence
- Impact assessment

## Project Structure

```
Societe_generale_VIT/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── config/                 # Configuration files
│   └── env.template        # Environment template
├── README.md              # This file
├── src/                   # Source code
│   ├── data_collection/    # Data collection modules
│   │   └── collector.py    # Multi-source data collector
│   ├── analysis/          # AI analysis modules
│   │   ├── triage_analyzer.py    # Ollama-based analysis
│   │   └── final_analyzer.py     # Claude-based final analysis
│   └── dashboard/         # Web interface
│       └── main_dashboard.py     # Gradio web dashboard
├── data/                  # Generated data files
│   ├── raw_articles.json  # Collected articles
│   └── triaged_articles.json # Analyzed articles
└── docs/                  # Documentation & outputs
    └── final_briefing.md  # Final threat briefing
```
