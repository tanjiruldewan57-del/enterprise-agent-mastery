# 🏛️ ApexVault AI: Level-4 Enterprise Multi-Tenant Treasury & Zero-Trust Agentic Architecture

> **Compliance Standard:** Level-4 Enterprise Banking Reference Architecture  
> **Mastery Curriculum:** 16 Competencies Mastered across Pillars 1, 2, and 3  
> **Test Suite:** 126 / 126 Automated Tests Passing (100% Green)  
> **Interface:** Dual-Pane Reactive Command Center with 4-Tier Horizon Architecture Flow Canvas  

---

## 🧭 Architecture Overview

ApexVault AI unifies **Agent Orchestration (Pillar 1)**, **Edge Guardrails & Privacy (Pillar 2)**, and a **Zero-Trust Data Tier (Pillar 3)** into a deterministic 16-stage defense matrix:

```
[ Ingress Inflow ]
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ 🛡️ TIER 1: EDGE GUARDRAILS & PRIVACY (PILLAR 2)       │
│ 01. Unicode Normalizer (NFKC + Zero-Width Stripper)    │
│ 02. Recursive De-cloaker (Base64/Hex Unpacker)         │
│ 03. Delimiter Firewall (ChatML/XML Token Shield)       │
│ 04. Zero-Knowledge PII Tokenizer Vault (UUIDv4)        │
│ 05. Semantic Vector Cache (<15ms Cosine Fast-Path)     │
│ 06. OWASP Top 10 Ingress Threat Guard                  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 🧠 TIER 2: COGNITIVE ORCHESTRATOR CORE (PILLAR 1)     │
│ 07. Multi-Agent Supervisor Router (Accounts/Tx/Service)│
│ 08. StateGraph & Reflexion Engine (Self-Healing Loop)  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 🔒 TIER 3: ZERO-TRUST DATA TIER & MCP (PILLAR 3)       │
│ 09. Decoupled MCP Subprocess (JSON-RPC 2.0 stdio IPC)  │
│ 10. Row-Level Security Engine (RLS Tenant Guard)       │
│ 11. AST SQL Validator (SQLGlot DDL/DML Block & Clamp)  │
│ 12. SQLite C-Level Authorizer (Kernel Callback Gate)   │
│ 13. Physical OS-Level Read-Only Vault (mode=ro URI)    │
│ 14. Multi-Tenant SQLite Database Execution             │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 🚀 TIER 4: EGRESS DELIVERY & PRIVACY RESTORATION       │
│ 15. OWASP Egress DLP Secret Redactor                   │
│ 16. PII De-tokenization & Semantic Cache Ingestion     │
└────────────────────────────────────────────────────────┘
```

---

## 📂 Repository Layout & Pillar Inventory

```
├── src/
│   ├── core/                        # Pillar 1: Orchestration Core
│   │   ├── state_machine.py         # 1.1 State Machines & Directed Graphs
│   │   ├── multi_agent_supervisor.py# 1.4 Supervisor & Domain Worker Pods
│   │   └── reflexion_engine.py      # 1.5 Cognitive Reflexion & Self-Healing
│   │
│   ├── state.py                     # 1.2 Channel-based State Reducers
│   ├── baseline_v0.py               # 1.3 Deterministic Baseline Execution
│   │
│   ├── guardrails/                  # Pillar 2: Edge Guardrails & Privacy
│   │   ├── owasp_threat_guard.py    # 2.1 OWASP LLM01 & LLM02 Threat Guard
│   │   ├── unicode_sanitizer.py     # 2.2 NFKC & Zero-Width Steganography
│   │   ├── obfuscation_decloaker.py # 2.3 Recursive Base64/Hex De-cloaker
│   │   ├── delimiter_firewall.py    # 2.4 Prompt Boundary Spoofing Shield
│   │   ├── semantic_cache.py        # 2.5 Vector Cosine Semantic Cache
│   │   ├── pii_vault.py             # 2.6 Zero-Knowledge PII Tokenizer Vault
│   │   ├── prompt_shield.py         # Unified Multi-Gate Guardrail Engine
│   │   │                            # Pillar 3: Zero-Trust Data Tier
│   │   ├── c_authorizer.py          # 3.1 SQLite C-Level Engine Authorizer
│   │   ├── read_only_vault.py       # 3.2 Physical URI mode=ro & Query-Only
│   │   ├── ast_sql_validator.py     # 3.3 SQLGlot AST Syntax & DDL/DML Clamping
│   │   └── multi_tenant_rls.py      # 3.4 Row-Level Security & BOLA Guard
│   │
│   └── mcp/                         # Pillar 3.5: Decoupled MCP Integration
│       ├── db_server.py             # Model Context Protocol stdio Subprocess
│       └── client.py                # Zero-Trust JSON-RPC MCP Client
│
├── gateway_app/                     # Unified Full-Stack Platform
│   ├── apex_pipeline.py             # Master 16-Stage Level-4 Execution Gateway
│   ├── server.py                    # Zero-Dependency Localhost HTTP Server
│   ├── seed_db.py                   # Multi-Tenant SQLite Database Seeder
│   └── static/
│       ├── index.html               # Framer-Grade Dual-Pane Command Console
│       └── app.js                   # Reactive Controller, 10 Scenarios & Horizon SVG
│
├── data/
│   └── apex_vault.db                # Multi-Tenant SQLite Database
│
└── tests/                           # 126 Automated Unit & Integration Tests
    ├── test_apex_platform_end_to_end.py # 10 Scenario End-to-End Test Suite
    └── test_*.py                    # Unit tests for all 16 competencies
```

---

## ⚡ Quick Start

### 1. Requirements & Setup
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Seed Database
```bash
python gateway_app/seed_db.py
```

### 3. Run ApexVault AI Command Console
```bash
python gateway_app/server.py 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 🧪 Automated Test Verification

Run all 126 tests across Pillars 1, 2, and 3:
```bash
pytest tests/ -v
```
*(All 126 tests pass in < 8 seconds with zero external network dependencies).*
