# RAG Chatbot with PII/PHI Guardrails
**Frameworks**: NIST AI RMF 1.0, ISO/IEC 42001, OWASP Top 10 for LLMs  
**Demo**: LLM Security Controls for Data Leakage Prevention

## 1. Purpose
This project demonstrates technical controls for **NIST AI RMF Measure 2.11** and **OWASP LLM06: Sensitive Information Disclosure**. 

A Retrieval-Augmented Generation (RAG) chatbot answers questions about company policy, but includes DLP guardrails that detect and block PII/PHI in both user prompts and LLM outputs.

## 2. Key Security Controls Implemented

| NIST AI RMF | Control | Implementation |
| --- | --- | --- |
| **Govern 1.1** | System prompts enforce policy | Hardcoded system prompt prohibits PII disclosure |
| **Map 2.3** | Data risk identification | Regex DLP scans for SSN, Email, PHI, API Keys |
| **Measure 2.11** | Test for data leakage | Automated redaction of PII in outputs |
| **Manage 4.1** | Post-deployment monitoring | Logs blocked requests for audit |

| OWASP LLM Top 10 | Risk | Mitigation |
| --- | --- | --- |
| **LLM01** | Prompt Injection | Input sanitization + refuse malicious prompts |
| **LLM06** | Sensitive Info Disclosure | Output DLP scanner + redaction |
| **LLM02** | Insecure Output Handling | Never execute LLM output, display only |

## 3. Architecture
