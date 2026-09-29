#!/usr/bin/env python3
"""
Vendor Security Review Automation - Main Script
Based on architecture.md requirements.
All external interactions are mocked for demo/production-ready base.
"""

import json
import logging
import os
import hashlib
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import tempfile
import shutil
from fpdf import FPDF

# --- Get script directory and set output path ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")

# --- CONFIGURATION ---
CONFIG = {
    "storage": {
        "s3_bucket": "vendor-security-archive",
        "local_backup_dir": OUTPUT_DIR,  # Files will be saved in output/ next to main.py
        "enable_versioning": True,
    },
    "notifications": {
        "ciso_email": "ciso@company.com",
        "slack_webhook": None,  # Would be set in production
    },
    "revaluation": {
        "frequency_days": 30,
        "notify_on_risk_change": True,
    },
    "ai_models": {
        "document_analysis": "claude-3-sonnet-20240229",
        "risk_scoring": "gpt-4-0613",
        "email_drafting": "llama-3-70b",
    },
}

# --- Create output directory if it doesn't exist ---
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# --- Custom JSON Encoder for Enum objects ---
class EnumEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Enum objects by converting them to their values"""
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)

# --- ENUMS & DATA STRUCTURES ---
class DataClassification(Enum):
    """Data classification levels for vendor risk assessment"""
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"

class VendorCategory(Enum):
    """Categories for vendor classification"""
    SAAS = "SaaS"
    API_INTEGRATION = "API Integration"
    DATA_PROCESSOR = "Data Processor"
    SOFTWARE = "Software"

class RiskLevel(Enum):
    """Risk levels for vendor assessment"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class Decision(Enum):
    """CISO decision options"""
    APPROVE = "Approve"
    REJECT = "Reject"
    REVIEW = "Review"

@dataclass
class VendorIntake:
    """Data structure for vendor intake form submission"""
    name: str
    url: str
    contact_email: str
    category: VendorCategory
    data_classification: DataClassification
    requester_name: str
    requester_team: str
    use_case_description: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ThirdPartyIntel:
    """Data structure for third-party intelligence collection"""
    security_score: int  # 0-100
    breach_history: List[Dict]
    open_ports: int
    vulnerabilities: int
    shodan_data: Dict
    virus_total_malicious: int

@dataclass
class ComplianceDocument:
    """Data structure for compliance documents"""
    name: str
    source: str  # "web", "vendor", "manual"
    content: str
    url: Optional[str] = None
    file_hash: Optional[str] = None
    collected_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class RiskAssessment:
    """Data structure for risk assessment results"""
    certification_compliance_score: float  # 0-100
    breach_history_score: float
    data_classification_score: float
    subprocessor_risk_score: float
    pentest_findings_score: float
    overall_score: float
    risk_level: RiskLevel
    llm_rationale: str

@dataclass
class CISODecision:
    """Data structure for CISO decision"""
    decision: Decision
    comments: str
    adjusted_score: Optional[float] = None
    decided_at: str = field(default_factory=lambda: datetime.now().isoformat())
    decided_by: str = "CISO"

@dataclass
class VendorReview:
    """Main data structure for vendor security review"""
    intake: Optional[VendorIntake] = None
    intel: Optional[ThirdPartyIntel] = None
    documents: Optional[List[ComplianceDocument]] = None
    risk_assessment: Optional[RiskAssessment] = None
    cisco_decision: Optional[CISODecision] = None
    archive_path: Optional[str] = None
    report_path: Optional[str] = None
    status: str = "INTAKE"

# --- MOCK EXTERNAL SERVICES ---
class MockSecurityScorecard:
    """Mock for SecurityScorecard API"""
    @staticmethod
    def get_score(domain: str) -> int:
        mock_data = {
            "google.com": 95, "microsoft.com": 92, "aws.amazon.com": 90,
            "github.com": 88, "unknown-vendor.com": 45, "risky-vendor.com": 25,
        }
        return mock_data.get(domain, 50)

    @staticmethod
    def get_breach_history(domain: str) -> List[Dict]:
        mock_data = {
            "google.com": [],
            "risky-vendor.com": [
                {"date": "2023-01-15", "severity": "High", "description": "Data breach affecting 10K users"},
                {"date": "2022-11-03", "severity": "Medium", "description": "API vulnerability exploited"},
            ],
            "unknown-vendor.com": [
                {"date": "2023-05-20", "severity": "Low", "description": "Minor security incident"},
            ],
        }
        return mock_data.get(domain, [])

class MockShodan:
    """Mock for Shodan API"""
    @staticmethod
    def scan_domain(domain: str) -> Dict:
        mock_data = {
            "google.com": {"open_ports": 2, "vulnerabilities": 0, "services": ["HTTP", "HTTPS"]},
            "github.com": {"open_ports": 3, "vulnerabilities": 0, "services": ["HTTP", "HTTPS", "SSH"]},
            "unknown-vendor.com": {"open_ports": 8, "vulnerabilities": 3, "services": ["HTTP", "FTP", "SSH", "RDP"]},
            "risky-vendor.com": {"open_ports": 15, "vulnerabilities": 7, "services": ["HTTP", "SMB", "RDP", "FTP"]},
        }
        return mock_data.get(domain, {"open_ports": 0, "vulnerabilities": 0, "services": []})

class MockVirusTotal:
    """Mock for VirusTotal API"""
    @staticmethod
    def check_domain(domain: str) -> int:
        mock_data = {"google.com": 0, "github.com": 0, "unknown-vendor.com": 2, "risky-vendor.com": 10}
        return mock_data.get(domain, 0)

class MockLLM:
    """Mock for LLM interactions (Claude, GPT, Llama)"""
    @staticmethod
    def analyze_documents(documents: List[ComplianceDocument], prompt: str) -> str:
        """Mock LLM document analysis"""
        doc_names = ", ".join([d.name for d in documents])
        return f"LLM Analysis: Reviewed {len(documents)} documents ({doc_names}). {prompt} - Mock response for demo."

    @staticmethod
    def evaluate_risk_criteria(text: str, criteria: str) -> Tuple[float, str]:
        """Mock LLM risk evaluation with score and rationale"""
        mock_evaluations = {
            "certification": (85, "Vendor has SOC 2 Type II and ISO 27001 certifications. Minor gaps in GDPR compliance."),
            "data_classification": (70, "Data handling aligns with Confidential classification but lacks encryption at rest."),
            "subprocessor": (60, "Uses 3 subprocessors with varying security postures. 1 subprocessor has recent breach."),
            "pentest": (75, "Last pentest was 6 months ago. 2 medium-severity findings were remediated."),
        }
        return mock_evaluations.get(criteria, (50, f"Default evaluation for {criteria}."))

    @staticmethod
    def generate_summary(review: VendorReview) -> str:
        """Generate summary without problematic f-strings"""
        concerns = []
        if review.intel.breach_history:
            concerns.append("Breach history")
        if review.intel.vulnerabilities > 5:
            concerns.append("High vulnerability count")
        primary_concerns = ", ".join(concerns) if concerns else "None"
        decision_text = review.cisco_decision.decision.value if review.cisco_decision else "Pending CISO Review"
        return (
            f"Executive Summary: {review.intake.name} ({review.intake.url}) has been reviewed. "
            f"Overall risk score: {review.risk_assessment.overall_score:.1f}/100 "
            f"({review.risk_assessment.risk_level.value}). "
            f"Primary concerns: {primary_concerns}. "
            f"Recommendation: {decision_text}."
        )

    @staticmethod
    def draft_email(vendor_contact: str, missing_docs: List[str]) -> str:
        """Mock LLM email drafting"""
        docs_list = "\n- ".join(missing_docs)  # Avoid backslash in f-string expression
        return f"""Subject: Request for Missing Compliance Documents

Dear Vendor Team,

We are conducting a security review for our potential partnership. To proceed, we require the following documents:
- {docs_list}

Please provide these at your earliest convenience.

Best regards,
Security Team
"""

# --- MOCK STORAGE & SERVICES ---
class MockS3Storage:
    """Mock for AWS S3 storage with versioning"""
    @staticmethod
    def upload_file(local_path: str, s3_key: str, bucket: str = None) -> str:
        bucket = bucket or CONFIG["storage"]["s3_bucket"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        versioned_key = f"{s3_key}_{timestamp}" if CONFIG["storage"]["enable_versioning"] else s3_key
        s3_path = f"s3://{bucket}/{versioned_key}"
        logger.info(f"Mock S3 Upload: {local_path} -> {s3_path}")
        return s3_path

class MockDrataAPI:
    """Mock for Drata API integration"""
    @staticmethod
    def sync_vendor_data(vendor_name: str, risk_data: Dict, decision: str) -> bool:
        logger.info(f"Mock Drata Sync: {vendor_name} - Risk: {risk_data['risk_level']}, Decision: {decision}")
        return True

    @staticmethod
    def trigger_workflow(workflow_name: str, vendor_data: Dict) -> bool:
        logger.info(f"Mock Drata Workflow: {workflow_name} triggered for {vendor_data['name']}")
        return True

class MockEmailService:
    """Mock for email sending"""
    @staticmethod
    def send_email(to: str, subject: str, body: str) -> bool:
        logger.info(f"Mock Email Sent - To: {to}, Subject: {subject}")
        return True

class PDFGenerator:
    """Generate PDF reports from markdown"""
    @staticmethod
    def from_markdown(markdown_text: str, output_path: str) -> str:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)  # Smaller font to avoid overflow

        # Set cell width for A4 page (190mm)
        cell_width = 190
        line_height = 6

        for line in markdown_text.split("\n"):
            if not line.strip():
                pdf.ln(line_height)
                continue

            if line.startswith("# "):
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, line_height, line[2:], ln=True)
                pdf.set_font("Arial", size=10)
            elif line.startswith("## "):
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, line_height, line[3:], ln=True)
                pdf.set_font("Arial", size=10)
            elif line.startswith("**") and line.endswith("**"):
                pdf.set_font("Arial", "B", 10)
                pdf.cell(0, line_height, line.strip("**"), ln=True)
                pdf.set_font("Arial", size=10)
            elif line.startswith("|"):
                # Handle tables with smaller font
                pdf.set_font("Arial", size=8)
                pdf.multi_cell(cell_width, line_height, line)
                pdf.set_font("Arial", size=10)
            else:
                pdf.multi_cell(cell_width, line_height, line)

        pdf.output(output_path)
        logger.info(f"PDF generated: {output_path}")
        return output_path

# --- CORE CLASS ---
class VendorSecurityReview:
    """Main class for vendor security review automation"""

    def __init__(self):
        self.review: Optional[VendorReview] = None
        self.temp_dir = os.path.join(OUTPUT_DIR, "temp")  # Temp directory inside output/
        os.makedirs(self.temp_dir, exist_ok=True)
        os.makedirs(CONFIG["storage"]["local_backup_dir"], exist_ok=True)

    def cleanup(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ==================== STAGE 1: INTAKE & TRIAGE ====================
    def create_intake_form(self, form_data: Dict) -> VendorIntake:
        """Process intake form data (mock form submission)"""
        logger.info("Processing intake form submission...")

        required_fields = ["name", "url", "contact_email", "category", "data_classification",
                          "requester_name", "requester_team", "use_case_description"]
        for field in required_fields:
            if field not in form_data:
                raise ValueError(f"Missing required field: {field}")

        return VendorIntake(
            name=form_data["name"],
            url=form_data["url"],
            contact_email=form_data["contact_email"],
            category=VendorCategory(form_data["category"]),
            data_classification=DataClassification(form_data["data_classification"]),
            requester_name=form_data["requester_name"],
            requester_team=form_data["requester_team"],
            use_case_description=form_data["use_case_description"],
        )

    # ==================== STAGE 2: DATA COLLECTION ====================
    def collect_third_party_intel(self, domain: str) -> ThirdPartyIntel:
        """Collect intelligence from third-party sources (mock APIs)"""
        logger.info(f"Collecting third-party intelligence for: {domain}")

        if domain.startswith(("http://", "https://")):
            domain = domain.split("//")[-1].split("/")[0]

        return ThirdPartyIntel(
            security_score=MockSecurityScorecard.get_score(domain),
            breach_history=MockSecurityScorecard.get_breach_history(domain),
            open_ports=MockShodan.scan_domain(domain)["open_ports"],
            vulnerabilities=MockShodan.scan_domain(domain)["vulnerabilities"],
            shodan_data=MockShodan.scan_domain(domain),
            virus_total_malicious=MockVirusTotal.check_domain(domain),
        )

    def collect_documents_from_web(self, vendor_url: str, use_case: str) -> List[ComplianceDocument]:
        """Mock: Collect regulatory documents from vendor website"""
        logger.info(f"Scraping {vendor_url} for compliance documents...")

        domain = vendor_url.split("//")[-1].split("/")[0]
        mock_documents = {
            "google.com": [
                {"name": "Google Cloud Security Whitepaper", "content": "Mock content...", "url": f"{vendor_url}/security/whitepaper"},
                {"name": "SOC 2 Type II Report", "content": "Mock SOC 2...", "url": f"{vendor_url}/compliance/soc2"},
            ],
            "github.com": [
                {"name": "GitHub Security Practices", "content": "Mock GitHub...", "url": f"{vendor_url}/security"},
            ],
            "unknown-vendor.com": [{"name": "Privacy Policy", "content": "Mock privacy...", "url": f"{vendor_url}/privacy"}],
        }

        docs = []
        for doc_info in mock_documents.get(domain, []):
            doc = ComplianceDocument(
                name=doc_info["name"],
                source="web",
                content=doc_info["content"],
                url=doc_info["url"],
                file_hash=hashlib.sha256(doc_info["content"].encode()).hexdigest(),
            )
            docs.append(doc)

        logger.info(f"Found {len(docs)} documents from web scraping")
        return docs

    def collect_documents_from_vendor(self, vendor_email: str, missing_docs: List[str]) -> List[ComplianceDocument]:
        """Mock: Request and collect documents from vendor via email"""
        logger.info(f"Requesting {len(missing_docs)} documents from vendor: {vendor_email}")

        email_body = MockLLM.draft_email(vendor_email, missing_docs)
        MockEmailService.send_email(vendor_email, "Request for Compliance Documents", email_body)

        received_docs = []
        for doc_name in missing_docs:
            if hash(doc_name) % 10 < 7:  # 70% chance of receiving
                received_docs.append(ComplianceDocument(
                    name=doc_name,
                    source="vendor",
                    content=f"Mock content for {doc_name}",
                    file_hash=hashlib.sha256(doc_name.encode()).hexdigest(),
                ))

        return received_docs

    def collect_manual_documents(self, requester_name: str, still_missing: List[str]) -> List[ComplianceDocument]:
        """Mock: Manual collection by requester/CISO"""
        logger.info(f"Manual collection required for {len(still_missing)} documents")

        doc_list = "\n- ".join(still_missing)  # Avoid backslash in f-string expression
        MockEmailService.send_email(
            requester_name,  # Using requester_name as recipient (mock)
            "Manual Document Collection Required",
            f"Please collect: {doc_list}",
        )

        return [ComplianceDocument(
            name=doc_name,
            source="manual",
            content=f"Mock content for {doc_name}",
            file_hash=hashlib.sha256(doc_name.encode()).hexdigest(),
        ) for doc_name in still_missing]

    def data_collection_pipeline(self, intake: VendorIntake) -> Tuple[ThirdPartyIntel, List[ComplianceDocument]]:
        """Execute full data collection pipeline"""
        logger.info("Starting data collection pipeline...")

        intel = self.collect_third_party_intel(intake.url)
        web_docs = self.collect_documents_from_web(intake.url, intake.use_case_description)
        all_docs = web_docs.copy()

        required_docs = {"SOC 2 Type II Report", "ISO 27001 Certification", "GDPR Compliance Statement"}
        collected_names = {d.name for d in all_docs}
        missing_docs = list(required_docs - collected_names)

        if missing_docs:
            vendor_docs = self.collect_documents_from_vendor(intake.contact_email, missing_docs)
            all_docs.extend(vendor_docs)
            collected_names.update({d.name for d in vendor_docs})
            missing_docs = list(required_docs - collected_names)

        if missing_docs:
            manual_docs = self.collect_manual_documents(intake.requester_name, missing_docs)
            all_docs.extend(manual_docs)

        logger.info(f"Data collection complete. Total documents: {len(all_docs)}")
        return intel, all_docs

    # ==================== STAGE 3: RISK ASSESSMENT ====================
    def assess_risk(self, intake: VendorIntake, intel: ThirdPartyIntel, documents: List[ComplianceDocument]) -> RiskAssessment:
        """Perform comprehensive risk assessment with weighted criteria"""
        logger.info("Starting risk assessment...")

        weights = {
            "certification_compliance": 0.30,
            "breach_history": 0.25,
            "data_classification": 0.15,
            "subprocessor_risk": 0.15,
            "pentest_findings": 0.15,
        }

        # 1. Certification & Compliance (30%)
        cert_score, cert_rationale = MockLLM.evaluate_risk_criteria(
            "\n".join([d.content for d in documents if "certification" in d.name.lower() or "compliance" in d.name.lower()]),
            "certification",
        )

        # 2. Breach History (25%)
        breach_score = 100.0
        for breach in intel.breach_history:
            severity_deduction = {"Low": 5, "Medium": 15, "High": 30, "Critical": 50}
            breach_score -= severity_deduction.get(breach["severity"], 10)
            if (datetime.now() - datetime.fromisoformat(breach["date"])).days < 365:
                breach_score -= 10
        breach_score = max(0, breach_score)

        # 3. Data Classification (15%)
        use_case_text = f"{intake.use_case_description}\nData Classification: {intake.data_classification.value}"
        data_class_score, _ = MockLLM.evaluate_risk_criteria(use_case_text, "data_classification")

        # 4. Subprocessor Risk (15%)
        subprocessor_score, _ = MockLLM.evaluate_risk_criteria(
            "\n".join([d.content for d in documents if "subprocessor" in d.name.lower()]),
            "subprocessor",
        )

        # 5. Pentest Findings (15%)
        pentest_score, _ = MockLLM.evaluate_risk_criteria(
            "\n".join([d.content for d in documents if "pentest" in d.name.lower()]),
            "pentest",
        )

        # Calculate weighted score
        overall_score = (
            cert_score * weights["certification_compliance"] +
            breach_score * weights["breach_history"] +
            data_class_score * weights["data_classification"] +
            subprocessor_score * weights["subprocessor_risk"] +
            pentest_score * weights["pentest_findings"]
        )

        # Determine risk level
        if overall_score >= 80:
            risk_level = RiskLevel.LOW
        elif overall_score >= 60:
            risk_level = RiskLevel.MEDIUM
        elif overall_score >= 40:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        llm_rationale = MockLLM.analyze_documents(
            documents,
            f"Rationale for score {overall_score:.1f} and risk level {risk_level.value}",
        )

        return RiskAssessment(
            certification_compliance_score=cert_score,
            breach_history_score=breach_score,
            data_classification_score=data_class_score,
            subprocessor_risk_score=subprocessor_score,
            pentest_findings_score=pentest_score,
            overall_score=overall_score,
            risk_level=risk_level,
            llm_rationale=llm_rationale,
        )

    # ==================== STAGE 4: RECOMMENDATION & CISO APPROVAL ====================
    def generate_recommendation(self, assessment: RiskAssessment) -> Decision:
        """Generate initial recommendation based on risk assessment"""
        if assessment.overall_score >= 80:
            return Decision.APPROVE
        elif assessment.overall_score >= 50:
            return Decision.REVIEW
        else:
            return Decision.REJECT

    def notify_ciso(self, review: VendorReview, recommendation: Decision) -> bool:
        """Notify CISO for approval"""
        logger.info(f"Notifying CISO for vendor: {review.intake.name}")
        summary = MockLLM.generate_summary(review)

        email_body = (
            f"Vendor Security Review Requires Your Attention\n\n"
            f"Vendor: {review.intake.name}\n"
            f"URL: {review.intake.url}\n"
            f"Risk Score: {review.risk_assessment.overall_score:.1f}/100\n"
            f"Risk Level: {review.risk_assessment.risk_level.value}\n"
            f"Initial Recommendation: {recommendation.value}\n\n"
            f"{summary}\n\n"
            f"Detailed Risk Assessment:\n"
            f"- Certification & Compliance: {review.risk_assessment.certification_compliance_score:.1f}\n"
            f"- Breach History: {review.risk_assessment.breach_history_score:.1f}\n"
            f"- Data Classification: {review.risk_assessment.data_classification_score:.1f}\n"
            f"- Subprocessor Risk: {review.risk_assessment.subprocessor_risk_score:.1f}\n"
            f"- Pentest Findings: {review.risk_assessment.pentest_findings_score:.1f}\n\n"
            f"LLM Rationale:\n{review.risk_assessment.llm_rationale}"
        )

        MockEmailService.send_email(
            CONFIG["notifications"]["ciso_email"],
            f"Vendor Review Required: {review.intake.name}",
            email_body,
        )
        return True

    def get_ciso_decision(self, review: VendorReview) -> CISODecision:
        """Mock: Simulate CISO decision (in production, this would come from UI/API)"""
        logger.info("Waiting for CISO decision (mock)...")

        if review.risk_assessment.overall_score >= 85:
            return CISODecision(
                decision=Decision.APPROVE,
                comments="All checks pass. Approved.",
                adjusted_score=review.risk_assessment.overall_score
            )
        elif review.risk_assessment.overall_score >= 70:
            return CISODecision(
                decision=Decision.APPROVE,
                comments="Minor concerns but acceptable.",
                adjusted_score=review.risk_assessment.overall_score + 5
            )
        elif review.risk_assessment.overall_score >= 50:
            return CISODecision(
                decision=Decision.REVIEW,
                comments="Requires manual verification.",
                adjusted_score=review.risk_assessment.overall_score
            )
        else:
            return CISODecision(
                decision=Decision.REJECT,
                comments="High risk due to breach history.",
                adjusted_score=review.risk_assessment.overall_score - 10
            )

    def generate_report(self, review: VendorReview, output_dir: str = None) -> Tuple[str, str]:
        """Generate markdown and PDF reports"""
        output_dir = output_dir or self.temp_dir
        os.makedirs(output_dir, exist_ok=True)
        vendor_name_safe = review.intake.name.replace(" ", "_")

        # Build markdown report line by line to avoid f-string issues
        lines = []
        lines.append("# Vendor Security Review Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().isoformat()}")
        lines.append(f"**Status:** {review.status}")
        lines.append(f"**CISO Decision:** {review.cisco_decision.decision.value if review.cisco_decision else 'Pending'}")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 1. Vendor Information")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Vendor Name** | {review.intake.name} |")
        lines.append(f"| **URL** | {review.intake.url} |")
        lines.append(f"| **Contact Email** | {review.intake.contact_email} |")
        lines.append(f"| **Category** | {review.intake.category.value} |")
        lines.append(f"| **Data Classification** | {review.intake.data_classification.value} |")
        lines.append(f"| **Requester** | {review.intake.requester_name} ({review.intake.requester_team}) |")
        lines.append("")
        lines.append("**Use Case Description:**")
        lines.append(review.intake.use_case_description)
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 2. Third-Party Intelligence")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Security Score** | {review.intel.security_score}/100 |")
        lines.append(f"| **Open Ports** | {review.intel.open_ports} |")
        lines.append(f"| **Vulnerabilities** | {review.intel.vulnerabilities} |")
        lines.append(f"| **VirusTotal Malicious** | {review.intel.virus_total_malicious} |")
        lines.append(f"| **Breach History** | {len(review.intel.breach_history)} incidents |")

        if review.intel.breach_history:
            lines.append("")
            lines.append("**Breach Details:**")
            for breach in review.intel.breach_history:
                lines.append(f"- {breach['date']}: {breach['severity']} - {breach['description']}")

        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 3. Compliance Documents Collected")
        lines.append("")
        lines.append("| Document | Source | Collected At |")
        lines.append("|----------|--------|--------------|")
        for d in review.documents:
            lines.append(f"| {d.name} | {d.source} | {d.collected_at} |")

        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 4. Risk Assessment")
        lines.append("")
        lines.append("### Weighted Scores")
        lines.append("")
        lines.append("| Criteria | Weight | Score | Contribution |")
        lines.append("|----------|--------|-------|--------------|")
        lines.append(f"| Certification & Compliance | 30% | {review.risk_assessment.certification_compliance_score:.1f} | {review.risk_assessment.certification_compliance_score * 0.30:.1f} |")
        lines.append(f"| Public Breach History | 25% | {review.risk_assessment.breach_history_score:.1f} | {review.risk_assessment.breach_history_score * 0.25:.1f} |")
        lines.append(f"| Data Classification & Use Case | 15% | {review.risk_assessment.data_classification_score:.1f} | {review.risk_assessment.data_classification_score * 0.15:.1f} |")
        lines.append(f"| Data Subprocessor Risk | 15% | {review.risk_assessment.subprocessor_risk_score:.1f} | {review.risk_assessment.subprocessor_risk_score * 0.15:.1f} |")
        lines.append(f"| Pentest Findings | 15% | {review.risk_assessment.pentest_findings_score:.1f} | {review.risk_assessment.pentest_findings_score * 0.15:.1f} |")
        lines.append(f"| **Overall Score** | **100%** | **{review.risk_assessment.overall_score:.1f}** | **{review.risk_assessment.overall_score:.1f}** |")
        lines.append("")
        lines.append(f"**Risk Level:** **{review.risk_assessment.risk_level.value}**")
        lines.append("")
        lines.append("### LLM Rationale")
        lines.append(review.risk_assessment.llm_rationale)
        lines.append("")
        lines.append("---")

        if review.cisco_decision:
            lines.append("")
            lines.append("## 5. CISO Decision")
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| **Decision** | {review.cisco_decision.decision.value} |")
            adjusted_score_str = f"{review.cisco_decision.adjusted_score:.1f}" if review.cisco_decision.adjusted_score else "N/A"
            lines.append(f"| **Adjusted Score** | {adjusted_score_str} |")
            lines.append(f"| **Comments** | {review.cisco_decision.comments} |")
            lines.append(f"| **Decided By** | {review.cisco_decision.decided_by} |")
            lines.append(f"| **Decided At** | {review.cisco_decision.decided_at} |")

        lines.append("")
        lines.append("---")
        lines.append("*This report was generated automatically by the Vendor Security Review System.*")
        markdown_report = "\n".join(lines)

        # Save files
        md_path = os.path.join(output_dir, f"vendor_report_{vendor_name_safe}.md")
        with open(md_path, "w") as f:
            f.write(markdown_report)

        pdf_path = os.path.join(output_dir, f"vendor_report_{vendor_name_safe}.pdf")
        PDFGenerator.from_markdown(markdown_report, pdf_path)
        return md_path, pdf_path

    # ==================== STAGE 5: EVIDENCE ARCHIVAL & GRC INTEGRATION ====================
    def archive_evidence(self, review: VendorReview, report_paths: Tuple[str, str]) -> str:
        """Archive all evidence and sync with GRC"""
        logger.info("Archiving evidence and syncing with GRC...")

        vendor_dir = os.path.join(
            CONFIG["storage"]["local_backup_dir"],
            review.intake.name.replace(" ", "_"),
            datetime.now().strftime("%Y%m%d"),
        )
        os.makedirs(vendor_dir, exist_ok=True)
        archive_files = []

        # Save JSON files
        for data, name in [
            (review.intake, "intake"),
            (review.intel, "intel"),
            (review.risk_assessment, "risk_assessment"),
        ]:
            path = os.path.join(vendor_dir, f"{name}.json")
            with open(path, "w") as f:
                json.dump(asdict(data), f, indent=2, cls=EnumEncoder)  # Use EnumEncoder for Enum serialization
            archive_files.append(path)

        # Save documents
        docs_dir = os.path.join(vendor_dir, "documents")
        os.makedirs(docs_dir, exist_ok=True)
        for i, doc in enumerate(review.documents):
            doc_path = os.path.join(docs_dir, f"{i}_{doc.name.replace(' ', '_')}.txt")
            with open(doc_path, "w") as f:
                f.write(doc.content)
            archive_files.append(doc_path)

        # Save reports
        for report_path in report_paths:
            dest = os.path.join(vendor_dir, os.path.basename(report_path))
            shutil.copy2(report_path, dest)
            archive_files.append(dest)

        # Mock S3 upload
        for local_path in archive_files:
            MockS3Storage.upload_file(local_path, os.path.relpath(local_path, CONFIG["storage"]["local_backup_dir"]))

        # Mock Drata sync
        MockDrataAPI.sync_vendor_data(
            review.intake.name,
            {
                "risk_score": review.risk_assessment.overall_score,
                "risk_level": review.risk_assessment.risk_level.value,
                "decision": review.cisco_decision.decision.value if review.cisco_decision else None,
            },
            review.cisco_decision.decision.value if review.cisco_decision else "Pending",
        )
        MockDrataAPI.trigger_workflow("vendor_review_completed", asdict(review.intake))
        return vendor_dir

    # ==================== STAGE 6: LOOPS (RE-EVALUATION) ====================
    def schedule_revaluation(self, review: VendorReview) -> bool:
        """Schedule periodic re-evaluation"""
        logger.info("Scheduling re-evaluation...")
        next_review = datetime.now() + timedelta(days=CONFIG["revaluation"]["frequency_days"])

        # Mock comparison with previous risk level
        previous_level = RiskLevel.MEDIUM
        if review.risk_assessment.risk_level != previous_level and CONFIG["revaluation"]["notify_on_risk_change"]:
            MockEmailService.send_email(
                CONFIG["notifications"]["ciso_email"],
                f"Risk Level Change: {review.intake.name}",
                f"Changed from {previous_level.value} to {review.risk_assessment.risk_level.value}",
            )

        logger.info(f"Next re-evaluation: {next_review.isoformat()}")
        return True

    # ==================== MAIN PIPELINE ====================
    def run_full_review(self, form_data: Dict) -> VendorReview:
        """Execute the complete vendor security review pipeline"""
        logger.info("=" * 60)
        logger.info("STARTING VENDOR SECURITY REVIEW PIPELINE")
        logger.info("=" * 60)

        review = VendorReview(status="INTAKE")

        try:
            # STAGE 1: Intake & Triage
            logger.info("\n[STAGE 1] INTAKE & TRIAGE")
            review.intake = self.create_intake_form(form_data)
            review.status = "TRIAGED"

            # STAGE 2: Data Collection
            logger.info("\n[STAGE 2] DATA COLLECTION")
            review.intel, review.documents = self.data_collection_pipeline(review.intake)
            review.status = "DATA_COLLECTED"

            # STAGE 3: Risk Assessment
            logger.info("\n[STAGE 3] RISK ASSESSMENT")
            review.risk_assessment = self.assess_risk(review.intake, review.intel, review.documents)
            review.status = "RISK_ASSESSMENT_COMPLETE"

            # STAGE 4: Recommendation & CISO Approval
            logger.info("\n[STAGE 4] RECOMMENDATION & CISO APPROVAL")
            recommendation = self.generate_recommendation(review.risk_assessment)
            self.notify_ciso(review, recommendation)
            review.cisco_decision = self.get_ciso_decision(review)
            review.status = "CISO_APPROVAL_COMPLETE"

            # Generate reports
            logger.info("\nGenerating reports...")
            md_path, pdf_path = self.generate_report(review)
            review.report_path = pdf_path

            # STAGE 5: Evidence Archival & GRC Integration
            logger.info("\n[STAGE 5] EVIDENCE ARCHIVAL & GRC INTEGRATION")
            review.archive_path = self.archive_evidence(review, (md_path, pdf_path))
            review.status = "ARCHIVED"

            # STAGE 6: Loops
            logger.info("\n[STAGE 6] LOOPS (RE-EVALUATION)")
            self.schedule_revaluation(review)
            review.status = "COMPLETE"

            logger.info("\n" + "=" * 60)
            logger.info("VENDOR SECURITY REVIEW COMPLETED SUCCESSFULLY")
            logger.info(f"Final Decision: {review.cisco_decision.decision.value}")
            logger.info(f"Archive Location: {review.archive_path}")
            logger.info("=" * 60)

            return review

        except Exception as e:
            logger.error(f"Review failed: {str(e)}")
            review.status = "FAILED"
            raise

# --- EXAMPLE USAGE ---
if __name__ == "__main__":
    # Example form data (would come from Google Forms/API in production)
    example_form_data = {
        "name": "Acme Data Services",
        "url": "https://acme-dataservices.com",
        "contact_email": "security@acme-dataservices.com",
        "category": "Data Processor",
        "data_classification": "Confidential",
        "requester_name": "Jane Doe",
        "requester_team": "Data Engineering",
        "use_case_description": (
            "We need to use Acme Data Services for processing our customer analytics. "
            "They will have access to our confidential customer data including PII. "
            "The service will be used to generate aggregated reports."
        ),
    }

    # Run the full review
    reviewer = VendorSecurityReview()
    try:
        result = reviewer.run_full_review(example_form_data)

        # Print summary
        print("\n" + "=" * 60)
        print("REVIEW SUMMARY")
        print("=" * 60)
        print(f"Vendor: {result.intake.name}")
        print(f"Risk Score: {result.risk_assessment.overall_score:.1f}/100")
        print(f"Risk Level: {result.risk_assessment.risk_level.value}")
        print(f"CISO Decision: {result.cisco_decision.decision.value}")
        print(f"Archive: {result.archive_path}")
        print(f"Report: {result.report_path}")
        print("=" * 60)

    finally:
        reviewer.cleanup()
