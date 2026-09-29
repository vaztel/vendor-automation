# 🔒 Vendor Security Review Automation

**Automated Vendor Security Assessment Pipeline**
*From Intake to Archival – A Production-Ready Framework*

---

## **📌 About The Project**

The **Vendor Security Review Automation** system is a **Python-based pipeline** designed to automate the entire vendor security assessment process, from initial intake to evidence archival and GRC integration. This project implements all 6 stages defined in `architecture.md` with **mocked external interactions** (APIs, LLMs, email, storage) for a **production-ready foundation**.

### **✨ Key Features**
- **End-to-End Automation**: Covers all 6 stages (Intake, Data Collection, Risk Assessment, CISO Approval, Archival, Loops)
- **Mocked Integrations**: Simulates SecurityScorecard, Shodan, VirusTotal, AWS S3, Drata, and LLM responses
- **Weighted Risk Scoring**: 5 criteria with configurable weights (30%, 25%, 15%, 15%, 15%)
- **Report Generation**: Automated **Markdown + PDF** reports with detailed risk breakdowns
- **Evidence Archival**: Structured local storage with versioning and S3 mock
- **Re-evaluation Loops**: Scheduled periodic reviews with risk change notifications
- **Extensible Design**: Easy to replace mocks with real API integrations

---

## **🏗️ Architecture Overview**

The pipeline follows a **6-stage workflow** as defined in `architecture.md`:

1. **📝 Intake & Triage**
   - Form validation (Google Forms/Typeform/Jira/custom)
   - Mandatory fields: Vendor name, URL, contact, category, data classification, requester details, use case

2. **🔍 Data Collection**
   - Third-party intelligence (SecurityScorecard, Shodan, VirusTotal)
   - Web scraping for compliance documents
   - Vendor email requests for missing documents
   - Manual collection fallback

3. **⚖️ Risk Assessment**
   - **Weighted scoring** across 5 criteria:
   Criteria                     | Weight | Method               |
 |------------------------------|--------|----------------------|
 | Certification & Compliance   | 30%    | Automated (code)     |
 | Public Breach History        | 25%    | Third-party scoring  |
 | Data Classification & Use Case | 15%  | LLM evaluation       |
 | Data Subprocessor Risk       | 15%    | LLM evaluation       |
 | Pentest Findings              | 15%    | LLM evaluation       |

4. **👔 Recommendation & CISO Approval**
   - Structured Markdown report generation
   - CISO notification (email/Slack)
   - Decision workflow (Approve/Reject/Review)
   - PDF report with final decision

5. **🗃️ Evidence Archival & GRC Integration**
   - Local storage with versioning
   - AWS S3 mock integration
   - Drata API mock synchronization
   - All documents stored in original form with metadata

6. **🔄 Loops**
   - Periodic re-evaluation (configurable frequency)
   - Risk change notifications
   - New document version retention

---

## **🚀 Getting Started**

### **Prerequisites**
- Python **3.9+** (tested on 3.9, 3.10, 3.11, 3.12)
- `pip` (Python package manager)

### **Installation**

1. **Clone the repository** (if applicable):
   ```bash
   git clone https://github.com/your-org/vendor-automation.git
   cd vendor-automation

### **First Run**

To run the Python script if Python is installed on your system:
> python3 scripts/main.py

Alternatively you could use the Docker image:
> docker compose up
