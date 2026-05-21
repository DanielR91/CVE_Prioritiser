# CVE "Exploitation In The Wild" Prioritiser

The CVE "Exploitation In The Wild" Prioritiser is a highly operational, serverless Vulnerability Intelligence console. It is designed to solve the biggest bottleneck in vulnerability management: **noise**.

In enterprise security, teams receive a daily feed of dozens of new vulnerabilities, almost all flagged as "High" or "Critical" based on their static CVSS score. This dashboard filters out the noise, cross-referencing theoretical severity ratings with real-world threat telemetry to pinpoint only the vulnerabilities that threat actors are actively weaponising in the wild.

---

## The Intelligence Architecture: Tri-Stream Data Correlation

The dashboard dynamically correlates three critical vulnerability intelligence feeds to build a unified prioritization model:

1. **The Baseline Data (NVD / MITRE CVE Feed):** Provides the foundational vulnerability list, descriptions, and the static **CVSS Score** (0.0 to 10.0 theoretical severity).
2. **The Predictive Telemetry (FIRST.org EPSS API):** The Exploit Prediction Scoring System uses a machine learning model updated daily to calculate a probability score from 0 to 1 (0% to 100%), predicting the likelihood that a CVE will be exploited in the wild over the next 30 days.
3. **The Empirical Fact (CISA KEV Catalog):** The Cybersecurity and Infrastructure Security Agency's "Known Exploited Vulnerabilities" catalog is the ultimate authority list. If a CVE is on this list, it is not a theory—it is a proven fact that an attacker has successfully weaponized it in the wild.

---

## The Triage Matrix (The Triage Quadrant)

Vulnerabilities are automatically sorted into a scannable, interactive quadrant grid based on severity and active threat telemetry:

| Category | Conditions | Tactical Action Required |
| :--- | :--- | :--- |
| **🚨 Immediate Patch** | High CVSS **AND** listed in CISA KEV | **Emergency patch cycle.** Active threat to production infrastructure. |
| **⚡ High Priority** | High CVSS **AND** High EPSS Score (>10%) | **Prioritize in the current sprint.** High probability of near-term weaponisation. |
| **⏳ Scheduled Patch** | High CVSS **BUT** Low EPSS / Not in KEV | **Standard maintenance cycle.** Theoretical danger, but no active exploit chatter. |
| **💤 Watchlist** | Low CVSS **AND** Low EPSS | **Deffered hygiene.** Safe to ignore or defer for baseline system hygiene. |

---

## Key Interface Features

### 1. Macro Analytics Panel
The header displays key metrics updated in real-time on every sync cycle:
*   **Total CVEs Tracked:** Comprehensive count of vulnerabilities in the database pool (Historical KEV + Recent 7-day feed).
*   **Confirmed Exploited (CISA KEV):** Number of active, proven exploits.
*   **Immediate Patch Required:** Count of active, weaponised threats matching the emergency criteria.
*   **High Probability:** Count of vulnerabilities with EPSS scores exceeding the 10% threshold.

### 2. Global Attack Surface Heatmap
A dynamic, interactive grid tracking which vendor ecosystems (e.g., Microsoft, Apple, Cisco, Adobe, Google) are taking the heaviest beating from threat actors.
*   **Visual Scaling:** Automatically adjusts block intensity (color and contrast) based on the vulnerability volume.
*   **Interactive Filtering:** Clicking on any vendor block instantly isolates their attack surface across the entire matrix.

### 3. High-Contrast Threat Grid
Cards are equipped with progressive visual indicators to make prioritization visual:
*   **Active KEV Alerts:** Vulnerabilities listed on the CISA KEV catalog blink with a glowing dark red pulsing border and a prominent `🚨 KEV` badge.
*   **EPSS Status Ring:** A circular progress meter indicates the EPSS probability percentage, color-scaled from green (low) to deep red (critical).
*   **CVSS Severity Badge:** Color-themed labels (Critical, High, Medium, Low) displaying the CVSS base score.

### 4. Interactive Remediation Drawer
Clicking a vulnerability card slides out a deep-dive remediation drawer:
*   **Tactical Recommendation:** Explains the exact remediation posture required for the security team.
*   **Ransomware Alert Banner:** If a vulnerability is actively used by ransomware groups (e.g., LockBit, Clop, BlackCat), a prominent warning is displayed.
*   **Remediation Instructions:** Copy-pasteable action plans derived directly from vendor and CISA recommendations.
*   **Advisories & Reference Links:** Quick-access links to official vendor security bulletins, patches, and NVD detail pages.

---

## Data Freshness & Automation
The dashboard is entirely self-updating. A GitHub Actions workflow triggers automatically once a day to pull the latest CISA KEV catalog, compile the NVD baseline feeds, query FIRST.org EPSS scores, and commit the updated datasets back to the repository. This ensures that the user is always looking at live, active vulnerability telemetry without needing manual inputs.
