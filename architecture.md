# **📄 Vendor Security Review Automation - Architecture Document**

---

## **Stages**
1. Intake & Triage
2. Data Collection
3. Risk Assessment
4. Recommendation & CISO Approval
5. Evidence Archival and GRC Integration
6. Loops

---

---
## **Intake & Triage**

We need a proper form for this process. This could be a **Google Form**, Typeform, another tool like Jira, or a custom form we code ourselves.
The form should capture at least the following:
- Vendor name, URL*, and contact
- Category*: SaaS / API Integration / Data Processor / Software
- Data Classification*: Public / Internal / Confidential / Restricted
- Requester details (name*, team)
- A short paragraph explaining which product we want to use, what we want to do, how we want to do it, and which problem it solves (the more specific, the better).

*Fields marked with * are mandatory.*

This could lead to further discussion about the difference between **pure vendor authorization** and **usage authorization** (e.g., restricted usage across all the vendor's products).

**Tool:** Google Forms, as the company already uses Google for email (as confirmed by DNS MX records). This ensures speed and seamless integration with existing tools.

---

---
## **Data Collection**

If any red flag is detected between steps, we **halt the investigation** and **generate an automated AI report as evidence**, which is sent to the requester. The CISO can always move the process forward if deemed relevant or necessary.

### **Steps:**
1. **Third-party intelligence**
   Sources: SecurityScorecard, Shodan, VirusTotal.
   Fully automated via simple API calls.

2. **Collect all regulatory documents from the internet**
   The list varies by use case; this is why the requester's input paragraph is critical.
   This step relies heavily on AI, is fully automated, and primarily involves scraping the vendor's website and other relevant sources to gather as much information as possible.

3. **Collect any remaining regulatory documents directly from the vendor**
   Only those missing from Step 2.
   This is fully automated: the AI drafts and sends an email to the most relevant contact to request missing documentation.

4. **Manually collect any remaining regulatory documents**
   Only those missing from Steps 2 and 3.
   The requester, assisted by the CISO, should contact the vendor directly to obtain the still-missing information.

**Tools:** Python for API calls, various LLMs/agents depending on the AI task required.

---

---
## **Risk Assessment**

The following categories should be assessed with **appropriate weights**. The goal is to generate a risk score with a **low/medium/high classification**.

| **Criteria**               | **Weight** | **How**                                      |
|----------------------------|------------|----------------------------------------------|
| Certification & Compliance | 30%        | No AI; automated via code. Missing compliance or certification lowers the score. |
| Public Breach History      | 25%        | Based on third-party scoring; automated via code. |
| Data Classification & Use Case | 15%    | LLM evaluation.                              |
| Data Subprocessor Risk    | 15%        | LLM evaluation.                              |
| Pentest Findings           | 15%        | LLM evaluation.                              |

**Tools:** Claude Cowork (or similar) provides excellent results for certification and compliance text interpretation.

---

---
## **Recommendation & CISO Approval**

The output is a **structured markdown report** that includes:
- Vendor details
- Detailed risk score
- LLM-generated summary
- LLM recommendation (Approve, Reject, or Review)

At this stage, the CISO is notified (via email/Slack/both) and must:
- Verify that the LLM evaluation from the Risk Assessment **makes sense**. The detailed risk score includes a detailed explanation of the LLM's scoring rationale.
- **Adjust the LLM's scoring** if deemed necessary.
- **Approve, Reject, or Review** (Review implies manual verification until approval or rejection is justified).

A final **PDF** is generated with the CISO's decision.

---

---
## **Evidence Archival and GRC Integration**

All collected information **must be stored** in an archiving system. Documents must be stored in their original form, with either **versioning** or the **upload date** included in the filename or metadata. This is accompanied by all generated information.

An **API call is sent to Drata** to:
- Synchronize data.
- Trigger relevant workflows (e.g., compliance checks).
All available custom controls should be included.

**Tool:** AWS S3 with **encryption** and **versioning**. This is secure, scalable, and easy to integrate, as AWS is already used by the company.

---
---
## **Loops**

Since most of the process is now automated, we can **re-evaluate all vendors at a set frequency**, potentially skipping manual data collection from vendors unless updated documents are required.

The CISO is **only notified** if the risk classification changes (e.g., from low to medium or medium to high).
All new document versions are retained, and new reports are generated if any changes occur.
