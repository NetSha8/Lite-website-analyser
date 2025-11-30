# Heimdall 🛡️

**Website Legitimacy Scanner** - Analyze URLs for potential phishing and fraud indicators.

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.123+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🌟 Features

- **Multi-factor Analysis**: 5 independent scoring modules
  - 🕐 Domain Age (WHOIS lookup)
  - 🔒 SSL Certificate validation
  - 🔗 URL Pattern analysis
  - 📄 Content Analysis (HTML/JS)
  - 🌐 DNS Analysis

- **Modern UI**: HTMX + Tailwind CSS with dark theme
- **Internationalization**: English & French support
- **High Performance**: 
  - Connection pooling
  - Multi-level caching (263x speedup on cached requests)
  - Parallel scoring execution

- **Security Hardened**:
  - SSRF protection
  - XSS prevention
  - Rate limiting (30 req/min)
  - Security headers (CSP, X-Frame-Options, etc.)
  - Input validation & sanitization

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/heimdall.git
cd heimdall

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload
```

Visit `http://localhost:8000` to access the UI.

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web UI |
| `POST` | `/api/analyze` | Analyze URL (HTMX response) |
| `POST` | `/api/analyze/json` | Analyze URL (JSON response) |
| `GET` | `/api/quick-check?url=...` | Quick check (URL + SSL only) |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/stats` | Cache statistics |

### Example API Usage

```bash
# Full analysis
curl -X POST http://localhost:8000/api/analyze/json \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Quick check
curl "http://localhost:8000/api/quick-check?url=https://example.com"
```

## 🏗️ Project Structure

```
heimdall/
├── main.py              # FastAPI application
├── security.py          # Security middleware & validation
├── cache.py             # Caching layer
├── http_client.py       # Shared HTTP client
├── i18n.py              # Internationalization
├── scorers/             # Scoring modules
│   ├── __init__.py
│   ├── base.py          # Base scorer class
│   ├── aggregator.py    # Score aggregation
│   ├── domain_age.py    # WHOIS-based scoring
│   ├── ssl_checker.py   # SSL certificate scoring
│   ├── url_analyzer.py  # URL pattern scoring
│   ├── content_analyzer.py  # HTML/JS scoring
│   └── dns_analyzer.py  # DNS scoring
└── templates/           # Jinja2 templates
    ├── index.html       # Main page
    └── results.html     # Results partial
```

## 🔒 Security Features

- **URL Validation**: Blocks dangerous schemes, injection attempts
- **SSRF Protection**: Blocks localhost, private IPs, cloud metadata endpoints
- **Rate Limiting**: 30 requests/minute, 200 requests/hour per IP
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, etc.
- **Cookie Security**: HttpOnly, SameSite=Strict
- **Error Sanitization**: HTML-escaped error messages

## ⚡ Performance

| Metric | Value |
|--------|-------|
| First request | ~1.5s |
| Cached request | ~6ms |
| Cache speedup | **263x** |

## 🌐 Internationalization

Supports English and French. Change language via:
- URL parameter: `/?lang=fr`
- Cookie (automatically saved)
- `Accept-Language` header

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [HTMX](https://htmx.org/) - High power tools for HTML
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS
- [python-whois](https://pypi.org/project/python-whois/) - WHOIS lookups
