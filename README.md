# Secure AI Gateway

Python proof-of-concept for a KEA bachelor thesis in IT Security. The gateway is a DLP proxy between a client and an external LLM API, designed to demonstrate how organisations under DORA and NIS2 can reduce prompt data leakage risk.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
python -m spacy download da_core_news_sm
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download da_core_news_sm
```

If the Danish spaCy model is not available, install the English fallback:

```bash
python -m spacy download en_core_web_sm
```

## Run In Demo Mode

Demo mode is enabled by default and does not require API keys.

```bash
uvicorn main:app --port 8000
```

Open `http://127.0.0.1:8000/` for the single-page UI.

## Run With A Real API Key

OpenAI on macOS/Linux:

```bash
export DEMO_MODE=false
export TARGET_API=openai
export OPENAI_API_KEY="sk-..."
uvicorn main:app --port 8000
```

OpenAI on Windows PowerShell:

```powershell
$env:DEMO_MODE="false"
$env:TARGET_API="openai"
$env:OPENAI_API_KEY="sk-..."
uvicorn main:app --port 8000
```

Anthropic uses `TARGET_API=anthropic` and `ANTHROPIC_API_KEY`.

## Run The Three Test Scenarios

```bash
python demo.py
```

The demo prints the original prompt, DLP result, policy decision, forwarded prompt, and sanitized audit entry for:

- CPR number in prompt: expected `BLOCK`
- Internal business data: expected `MASK_AND_FORWARD`
- Neutral regulation prompt: expected `ALLOW`

## Audit Log

The gateway writes JSONL entries to `audit.log` by default. The log stores metadata only: request ID, target endpoint, original prompt length, entity labels/stages, policy action, policy rule, AUP reference, and forwarding status. It must not contain original prompt text or original sensitive values.

