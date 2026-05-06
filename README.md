# Secure AI Gateway

Secure AI Gateway er en Python proof-of-concept udviklet til et bachelorprojekt i IT-sikkerhed på KEA. Projektet undersøger, hvordan organisationer under DORA og NIS2 kan reducere risikoen for datalækage, når medarbejdere bruger eksternt hostede LLM-tjenester som ChatGPT, Claude og Gemini.

Applikationen fungerer som en DLP-proxy mellem brugeren og en ekstern LLM API. Før en prompt sendes videre, bliver den analyseret for følsomme oplysninger, vurderet af en policy engine, eventuelt maskeret eller blokeret, og derefter logget i en sanitiseret audit-log.

## Formål

Projektet demonstrerer en teknisk kontrol, som kan placeres mellem interne brugere og eksterne AI-tjenester. Gatewayen er bygget til at understøtte thesis-argumentet om, at en proxy-arkitektur kan bruges som en praktisk kontrol mod OWASP LLM02-risici og som led i styring af IKT-tredjepartsrisiko under DORA artikel 28 og NIS2 artikel 21.

PoC'en fokuserer på inputkontrol. Den filtrerer og vurderer prompts, før de forlader organisationens miljø. Den implementerer ikke IAM, database, TLS-terminering, outputfiltrering eller containerisering, da disse dele er afgrænset fra bachelorprojektets scope.

## Centrale Funktioner

- OpenAI-kompatibel gateway-endpoint: `POST /v1/chat/completions`
- Streaming-endpoint med Server-Sent Events: `POST /v1/chat/completions/stream`
- Single-page demo UI på `GET /`
- Health-check på `GET /health`
- Demo-auditvisning på `GET /audit`
- Regex-baseret detektion af CPR, IBAN, kreditkort, API-nøgler og e-mail
- spaCy NER-detektion af personer og organisationer
- Regelbaseret policy engine med `ALLOW`, `MASK_AND_FORWARD` og `BLOCK`
- Dansk AUP-besked ved blokering
- Maskering med danske tokens som `[CPR-MASKERET]` og `[EMAIL-MASKERET]`
- JSONL audit-log uden original prompttekst eller originale følsomme værdier
- Demo mode uden API-nøgler
- Understøttelse af OpenAI, Anthropic, Gemini og mock/demo target

## Arkitektur

```text
Bruger / klient
      |
      v
FastAPI Gateway
      |
      v
DLP Pipeline
  1. Regex-detektion
  2. spaCy NER
      |
      v
Policy Engine
  - ALLOW
  - MASK_AND_FORWARD
  - BLOCK
      |
      +--> Audit Logger
      |
      v
Ekstern LLM API eller demo/mock response
```

Gatewayen bruger et sekventielt flow: prompten analyseres først, derefter træffes en policy-beslutning, og først derefter kan data sendes videre. Ved `BLOCK` forlader prompten aldrig gatewayen. Ved `MASK_AND_FORWARD` sendes kun den maskerede prompt videre.

## Projektstruktur

```text
secure_ai_gateway/
├── main.py              # FastAPI app og HTTP gateway
├── dlp_pipeline.py      # Regex + NER DLP-pipeline
├── masker.py            # Maskering af detekterede entiteter
├── policy_engine.py     # Regelbaseret policy-beslutning
├── audit_logger.py      # Sanitiseret JSONL audit-log
├── aup.py               # Danske Acceptable Use Policy-beskeder
├── config.py            # Miljøvariabler og defaults
├── demo.py              # Standalone demo med tre testscenarier
├── templates/
│   └── index.html       # Vanilla HTML/CSS/JS demo UI
└── requirements.txt

main.py                  # Root wrapper til uvicorn main:app
demo.py                  # Root wrapper til python demo.py
requirements.txt         # Installationskrav
```

## DLP Pipeline

Pipeline består af to trin.

Trin 1 er regex-detektion:

- Dansk CPR-nummer: `CPR_NUMBER`
- IBAN: `IBAN`
- Kreditkort: `CREDIT_CARD`
- API-nøgle eller bearer-token: `API_KEY`
- E-mailadresse: `EMAIL`

Trin 2 er NER-detektion via spaCy:

- `PERSON` markeres som følsom
- `ORG` markeres som følsom
- `GPE` kan detekteres som lavere risiko, men maskeres ikke som standard

Resultatet returneres som en `DLPResult` med detekterede entiteter og samlet risikoniveau: `NONE`, `LOW` eller `HIGH`.

## Policy Engine

Policy engine bruger fem prioriterede regler:

1. `HIGH` + CPR eller IBAN betyder `BLOCK`
2. `HIGH` + API-nøgle betyder `BLOCK`
3. `HIGH` + kreditkort betyder `MASK_AND_FORWARD`
4. `LOW` med e-mail, person eller organisation betyder `MASK_AND_FORWARD`
5. `NONE` betyder `ALLOW`

Beslutningen returneres som en `PolicyDecision` med handling, dansk forklaring, regelnummer og reference til AUP.

## Maskering

Når gatewayen vælger `MASK_AND_FORWARD`, erstattes følsomme værdier med faste tokens:

| Entitet | Token |
| --- | --- |
| `CPR_NUMBER` | `[CPR-MASKERET]` |
| `IBAN` | `[IBAN-MASKERET]` |
| `CREDIT_CARD` | `[KREDITKORT-MASKERET]` |
| `API_KEY` | `[API-NØGLE-MASKERET]` |
| `EMAIL` | `[EMAIL-MASKERET]` |
| `PERSON` | `[NAVN-MASKERET]` |
| `ORG` | `[ORG-MASKERET]` |

Originale værdier sendes aldrig videre til LLM API'et. Mappingen bruges kun internt i gatewayens behandlingsflow og audit-metadata angiver kun, om der blev gemt maskeringsmapping, ikke hvilke værdier der blev maskeret.

## Audit Log

Audit-loggen skrives som newline-delimited JSON i `audit.log`. Hver entry indeholder kun metadata:

- `timestamp`
- `request_id`
- `target_api`
- `original_prompt_length`
- `detected_entities` som label og stage
- `masked_values_stored`
- `policy_action`
- `policy_rule_triggered`
- `aup_reference`
- `forwarded_to_llm`

Audit-loggen må ikke indeholde original prompttekst, CPR-numre, e-mails, API-nøgler eller andre originale følsomme værdier.

## UI

Demo-siden på `http://127.0.0.1:8000/` er bygget med vanilla HTML, CSS og JavaScript. Den har:

- Chat-lignende promptfelt
- Knapper til valg af target: OpenAI, Anthropic, Gemini eller Mock
- Streaming-svar med typing-effekt
- Rødt resultatkort ved `BLOCK`
- Gult resultatkort ved `MASK_AND_FORWARD`
- Grønt resultatkort ved `ALLOW`
- Udvidelig audit-entry, som kan bruges i rapport eller screenshots

Hvis Gemini eller en anden provider afviser et API-kald, vises fejlen som et rødt provider-fejlkort. DLP-beslutningen vises ikke som en succesfuld videresendelse, hvis selve LLM-kaldet fejler.

## Installation

Python 3.11 anbefales.

macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
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

Hvis den danske spaCy-model ikke kan installeres, kan den engelske fallback installeres:

```bash
python -m spacy download en_core_web_sm
```

## Kørsel I Demo Mode

Demo mode er standard og kræver ingen API-nøgler.

```bash
uvicorn main:app --port 8000
```

Åbn derefter:

```text
http://127.0.0.1:8000/
```

## Kørsel Med Gemini

Gemini bruger Googles OpenAI-kompatible endpoint:

```text
https://generativelanguage.googleapis.com/v1beta/openai/
```

Windows PowerShell:

```powershell
$env:DEMO_MODE="false"
$env:TARGET_API="gemini"
$env:GEMINI_API_KEY="<din-gemini-api-key>"
uvicorn main:app --port 8000
```

macOS/Linux:

```bash
export DEMO_MODE=false
export TARGET_API=gemini
export GEMINI_API_KEY="<din-gemini-api-key>"
uvicorn main:app --port 8000
```

Hvis `GEMINI_API_KEY` er sat, og `TARGET_API` ikke er sat, vælger gatewayen Gemini som default target.

## Kørsel Med OpenAI Eller Anthropic

OpenAI:

```powershell
$env:DEMO_MODE="false"
$env:TARGET_API="openai"
$env:OPENAI_API_KEY="<din-openai-api-key>"
uvicorn main:app --port 8000
```

Anthropic:

```powershell
$env:DEMO_MODE="false"
$env:TARGET_API="anthropic"
$env:ANTHROPIC_API_KEY="<din-anthropic-api-key>"
uvicorn main:app --port 8000
```

## Demo Scenarier

Kør de tre thesis-scenarier:

```bash
python demo.py
```

Demoen printer:

- Scenarienavn og forventet outcome
- Original prompt
- Detekterede entiteter med label og stage
- Policy decision, regelnummer og forklaring
- Hvad der ville blive sendt videre til LLM
- Sanitiseret audit-entry som pretty-printed JSON

Scenarierne er:

1. CPR-nummer i prompt: forventer `BLOCK`
2. Forretningsdata med navn og e-mail: forventer `MASK_AND_FORWARD`
3. Neutral faglig prompt: forventer `ALLOW`

## Endpoints

| Endpoint | Metode | Formål |
| --- | --- | --- |
| `/` | `GET` | Demo UI |
| `/health` | `GET` | Gateway-status |
| `/audit` | `GET` | Sidste 20 audit-entries |
| `/v1/chat/completions` | `POST` | Ikke-streamende gateway-kald |
| `/v1/chat/completions/stream` | `POST` | Streaming gateway-kald via SSE |

Eksempel på request body:

```json
{
  "messages": [
    {
      "role": "user",
      "content": "Skriv din prompt her"
    }
  ],
  "model": "gpt-4o-mini",
  "target": "gemini"
}
```

## Konfiguration

Miljøvariabler:

| Variabel | Default | Beskrivelse |
| --- | --- | --- |
| `OPENAI_API_KEY` | `None` | API-nøgle til OpenAI |
| `ANTHROPIC_API_KEY` | `None` | API-nøgle til Anthropic |
| `GEMINI_API_KEY` | `None` | API-nøgle til Gemini |
| `TARGET_API` | `mock` eller `gemini` hvis Gemini-key er sat | Valgt target |
| `TARGET_MODEL` | `gpt-4o-mini` | Standardmodel |
| `GATEWAY_PORT` | `8000` | Lokal port |
| `DEMO_MODE` | `true` | Slår eksterne API-kald fra |
| `LOG_FILE` | `audit.log` | Audit-logsti |

## Sikkerhedsafgrænsning

Projektet er en proof-of-concept og ikke en færdig produktionsgateway. Følgende er bevidst uden for scope:

- Brugerlogin og IAM
- Database
- TLS/HTTPS-terminering
- Rate limiting
- Outputfiltrering
- Docker/containerisering
- Central SIEM-integration

Disse elementer kan beskrives som videreudvikling i rapporten, mens PoC'en fokuserer på den centrale thesis-kontrol: prompt scanning, policy decision, maskering/blokering og audit.

## Validering

Før aflevering kan følgende checks køres:

```bash
python demo.py
python -m compileall secure_ai_gateway main.py demo.py
uvicorn main:app --port 8000
```

Efter `python demo.py` bør `audit.log` eksistere og indeholde gyldig JSONL uden originale prompts eller følsomme værdier.
