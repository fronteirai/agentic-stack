About Kovrr
Kovrr quantifies cyber risk for enterprises - we integrate with security tools, process large volumes of data, and translate technical threats into financial impact for CISOs and boards.

The Task: Vulnerability Risk Dashboard
Build a mini full-stack app that fetches vulnerability data, calculates risk scores, and displays results.

Part 1: Backend
Tech: Node.js | Supabase (there's a .env file in the root with the `SUPABASE_URL` variable you can leverage to connect)

API Source - NVD (no auth required): 
GET https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20
View a sample api response at: docs/nvd-api.md

Required Endpoints:
• GET /api/vulnerabilities - List with filtering (?severity=HIGH)
• GET /api/vulnerabilities/:id - Single item details
• GET /api/stats - Count by severity, top vendors

Risk Score (0-100): Calculate based on CVSS score (60%), exploitability (20%), age (20%). Document your formula.

Requirements: Error handling for API failures, 2-3 unit tests

Part 2: Frontend
Tech: React + TypeScript | Styling: your choice (Tailwind, MUI, CSS)

Required Components:
A. Vulnerability Table
   • Columns: CVE ID, Description, Severity, Risk Score, Date
   • Sortable by Risk Score | Filterable by Severity

B. Risk Score Indicator
   • Color-coded: Green (0-30), Yellow (31-60), Orange (61-80), Red (81-100)

C. Stats Panel
   • Severity breakdown (chart optional)

AI Tools Usage
We encourage Cursor!
In your README, include:
• Which AI tools you used
• What you used them for
• What you modified/improved from AI suggestions


Evaluation Criteria
• Code Quality (30%) - Clean, readable, well-structured
• Functionality (30%) - Features work correctly
• Data Handling (20%) - API integration, error handling
• Frontend UX (10%) - Intuitive and clear
• AI Usage (10%) - Effective use while maintaining ownership
