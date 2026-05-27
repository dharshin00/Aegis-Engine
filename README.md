# 🛡️ Project Aegis  
## A Neuro-Symbolic Graph and Dynamic Deception Architecture for Database Insider Threat Detection

Project Aegis is an AI-powered cybersecurity framework designed to detect and automatically mitigate insider threats at the database level using Graph Neural Networks (GNNs), Transformer-based SQL intent analysis, and dynamic deception technology.

The system combines behavioral analytics, graph-based anomaly detection, explainable AI, and automated database lockdown mechanisms to stop malicious insiders and compromised accounts in real-time.

---

# 🚀 Features

- Real-time database monitoring
- AI-powered insider threat detection
- Graph Neural Network (GNN) anomaly analysis
- Transformer-based SQL intent classification
- CTGAN-generated honeytokens
- Automated attacker isolation
- Explainable AI threat analysis
- Real-time intelligence dashboard
- Dockerized PostgreSQL environment
- Active mitigation using PostgreSQL backend termination

---

# 🛠️ Tech Stack

## Artificial Intelligence & Machine Learning
- PyTorch
- PyTorch Geometric
- Graph Neural Networks (GCNConv)
- DistilBERT
- GNNExplainer
- CTGAN

## Backend
- FastAPI
- Python
- AsyncPG
- Uvicorn

## Database
- PostgreSQL
- SQL Triggers
- pg_notify Event System

## Frontend
- HTML
- CSS
- JavaScript

## Deployment & Tools
- Docker
- Docker Compose
- GitHub

---

# 📂 Project Structure

```bash
Aegis-Engine-main/
│
├── aegis_engine/
│   ├── main.py
│   ├── db_listener.py
│   ├── gnn_model.py
│   ├── simulate_attack.py
│   ├── requirements.txt
│   └── static/
│       └── index.html
│
├── docker-compose.yml
├── aegis_setup.sql
└── README.md
```

---

# 🎯 Problem Statement

Traditional cybersecurity systems rely heavily on static rule-based monitoring and perimeter defense, making them ineffective against insider threats operating with valid credentials.

Project Aegis addresses this challenge using:
- Behavioral graph analysis
- AI-driven SQL understanding
- Dynamic deception mechanisms
- Real-time automated mitigation

---

# 🏗️ System Architecture

Project Aegis consists of two major operational components:

## 1️⃣ Database Sphere

Responsible for:
- Logging database activities
- Maintaining honeytokens
- Triggering asynchronous notifications
- Detecting suspicious row-level access

### Main Files

### `docker-compose.yml`
Creates an isolated PostgreSQL environment.

### `aegis_setup.sql`
Initializes:
- Audit schema
- Honeytoken registry
- Change logs
- Trigger functions
- Real-time notification channels

Uses:

```sql
pg_notify()
```

to asynchronously send attack events to the AI engine.

---

## 2️⃣ Intelligence Engine Sphere

Responsible for:
- Listening to database events
- AI threat evaluation
- Real-time mitigation
- Dashboard communication

### Main Files

### `main.py`
Acts as the FastAPI command center.

### `db_listener.py`
Handles:
- PostgreSQL event listening
- Threat evaluation
- Automated mitigation

If threat score exceeds 80%:
- Terminates attacker session
- Locks compromised account
- Rolls back malicious transactions

### `gnn_model.py`
Contains:
- Graph Neural Network architecture
- Behavioral anomaly detection
- Explainable AI logic

### `simulate_attack.py`
Used to simulate insider attacks during demonstrations.

### `static/index.html`
Real-time monitoring dashboard.

---

# 🤖 Artificial Intelligence Models

## Graph Neural Networks (GNNs)

The system models database activities as session graphs.

### Nodes Represent:
- Users
- Queries
- Tables
- Operations
- Login events

The GNN learns:
- Normal behavioral patterns
- Query relationships
- Lateral movement structures

This enables:
- Node-level anomaly detection
- Session-level anomaly detection
- Structural attack pattern recognition

---

## SQL Intent Analysis using DistilBERT

Project Aegis treats SQL queries as natural language.

DistilBERT helps classify:
- Routine queries
- Bulk exfiltration attempts
- Unauthorized access patterns
- Suspicious intent

Benefits:
- Detects obfuscated queries
- Understands semantic intent
- Improves detection accuracy

---

## CTGAN Honeytoken Deception

Project Aegis generates realistic fake records using CTGAN.

These honeytokens:
- Mimic real sensitive data
- Match statistical distributions
- Act as deception traps

If accessed:
- Immediate high-confidence alert is generated
- Near-zero false positives

---

# 🔍 Explainable AI (XAI)

Project Aegis integrates:

## GNNExplainer

This helps:
- Identify suspicious graph structures
- Explain why an alert was triggered
- Provide analysts with threat reasoning

---

# ⚡ Automated Active Mitigation

If the threat score exceeds the threshold:

```python
Threat Score > 80%
```

the system automatically executes:

```sql
pg_terminate_backend(pid)
```

This:
- Disconnects attacker instantly
- Stops data exfiltration
- Rolls back malicious operations
- Locks compromised session

---

# 🌐 Dashboard Features

- Live attack feed
- Threat analytics
- AI explainability insights
- Attack history
- Isolated users list
- Real-time mitigation updates

---

# ⚙️ Installation & Setup

## 1️⃣ Clone Repository

```bash
git clone https://github.com/your-username/project-aegis.git

cd project-aegis
```

---

## 2️⃣ Start PostgreSQL Environment

```bash
docker compose up -d
```

---

## 3️⃣ Navigate to Intelligence Engine

```bash
cd aegis_engine
```

---

## 4️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 5️⃣ Start FastAPI Server

```bash
uvicorn main:app --reload
```

---

## 6️⃣ Open Dashboard

```bash
http://127.0.0.1:8000
```

---

# 🧪 Demonstration Workflow

## Step 1 — Login to Dashboard

Open:

```bash
localhost:8000
```

---

## Step 2 — Simulate Insider Attack

Run:

```bash
python simulate_attack.py
```

---

## Step 3 — Real-Time Detection

The system:
- Receives asynchronous notifications
- Evaluates query graph
- Generates AI threat score
- Updates dashboard instantly

---

## Step 4 — Automated Lockdown

If attack is critical:
- User session terminated
- Database process killed
- Attacker isolated
- Transactions rolled back

---

# 📈 Future Enhancements

- Zero Trust Identity Integration
- Multi-database support
- SIEM integration
- Cloud deployment
- Advanced NLP models
- Adaptive threat intelligence
- Multi-user SOC dashboard

---

# 📄 License

This project is developed for educational and research purposes.
