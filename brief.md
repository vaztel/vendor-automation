# **📄 Vendor Security Review Automation - Implementation Brief**

---

## **Next Steps**

If I had another full day, I would prioritize the following tasks in order of **cost-effectiveness** (balancing implementation effort against manual work saved per vendor):

1. **Investigate AI/LLM applications**
   Evaluate how AI/LLM can be applied to each step of the workflow, assessing both the implementation effort required and the expected results. Currently, I lack sufficient awareness of all available options.

2. **Prioritize remaining tasks**
   Assuming AI/LLM implementation is the most resource-intensive component, I would prioritize the following (ordered by cost vs. effectiveness):
   - Input data form (quick to implement using Google Forms)
   - Data storage and global workflow structure
   - Complete scoring engine (excluding LLM components)
   - GRC integration (to push data and maintain consistency as soon as possible)
   - LLM-enhanced scoring engine and report generation
   - AI for automatic vendor contact to request specific documentation
   - Long-term vendor monitoring logic

---
---
## **Trade-Offs**

| **Decision** | **Rationale** |
|--------------|---------------|
| **Use mock APIs** | Accelerates development and reduces costs during prototyping. |
| **Python as the language** | Widely used and considered easy to learn. However, we should switch to another language (e.g., Go, Rust) if the company is more proficient in it. |
| **No custom front-end** | Building a front-end from scratch is not the most time-saving feature at this stage. |
| **AI/LLM/agents role** | These tools should **never make autonomous decisions**. Their purpose is to gather data, structure it, summarize it, and adopt a risk/security perspective in their analysis. |

### **AI/LLM Output Structure**
To support the CISO's decision-making, AI/LLM analyses should consistently present three elements:
1. **Extracted data** from the source document.
2. **Interpretation** of the extracted data and an overall assessment of the document and vendor.
3. **Scoring conclusion** based on the analysis.

This structure enables the CISO to:
- Identify if the LLM missed critical information (e.g., privacy policy, but LLM detected nothing about what happens with the data), triggering cross-LLM review or manual document review.
- Gain an overview of the document as if they had read it themselves, helping to spot poor quality, inconsistencies, or the need for manual review.
- Directly apply the recommendation if they agree, saving time.

---
---
## **Risks and Mitigations**

### **Biggest Risk**
The primary risk is **missing critical risks during the LLM-based scoring process**.

### **Mitigation Strategy**
- **Human oversight**: All AI analyses must be logged and retained, including email exchanges (with copies sent to relevant recipients).
- **Structured output**: Every analysis should include both the extracted data and its interpretation for human review.
- **Decision boundary**: The AI should **never make decisions**—all final determinations remain with the CISO.
