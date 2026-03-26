# 🛡️ CyberScan Pro

### Network Cyber Risk & Threat Intelligence Platform

---

## 🚀 Overview

CyberScan Pro is a **full-stack cybersecurity platform** that performs real-time **network scanning, threat intelligence enrichment, and risk analysis**.

It combines tools like **Nmap + VirusTotal + Streamlit + FastAPI** to simulate a real-world **Security Operations Center (SOC) system**.

The platform provides:

* 📊 Interactive dashboard
* 🚨 Risk-based vulnerability analysis
* 📩 Email alerts for critical issues
* 📄 PDF report generation
* 💾 Scan history tracking

---

## 🎯 Key Features

### 🔍 Network Scanning (Nmap)

* Detects:

  * Open ports
  * Running services
  * Product & version
* Uses: `nmap -sV`

---

### 🌐 Threat Intelligence (VirusTotal)

* Enriches scan data with:

  * Malicious reports
  * Suspicious counts
  * Reputation score
  * Country & network
  * Threat categories

---

### 🧠 Risk Analysis Engine

Each service is scored using:

| Score Type     | Description                                 |
| -------------- | ------------------------------------------- |
| Exposure Score | Risk of exposed service (e.g., Telnet, RDP) |
| Threat Score   | Based on VirusTotal reports                 |
| Context Score  | Country + threat category                   |
| Risk Score     | Final weighted score                        |

---

### 🚨 Severity Classification

* 🟢 Low
* 🟡 Medium
* 🟠 High
* 🔴 Critical

---

### 📊 Interactive Dashboard (Streamlit)

* KPI Cards (IP, Ports, Risk, Threat)
* 📈 Bar charts (Score breakdown)
* 🥧 Pie chart (Risk distribution)
* 🔥 Heatmap visualization
* 🌐 Services detected
* 📜 Scan history
* 📈 Risk trends over time

---

### 📩 Email Alerts

* Automatically sends email after scan
* Highlights:

  * Critical vulnerabilities
  * Recommendations

---

### 📄 PDF Report Generation

* Generates downloadable report
* Includes:

  * Summary
  * Findings
  * Risk levels
  * Recommendations

---

### ⚡ FastAPI Backend

* Provides API endpoints for:

  * Scan data
  * History
  * Analysis
* Secured using API Key

---

### 💾 Database (SQLite)

* Stores:

  * Scan results
  * Risk scores
  * History

---

## 🗂️ Project Structure

```
cyberisk_platform/
│
├── modules/
│   ├── scanner.py
│   ├── analyser.py
│   ├── database.py
│   ├── emailer.py
│   ├── pdf_generator.py
│
├── dashboard/
│   ├── app.py
│
├── api.py
├── requirements.txt
├── .env
└── cyberscan.db
```

---

## ⚙️ Setup Instructions

### 1️⃣ Clone Project

```bash
git clone <your-repo-url>
cd cyberisk_platform
```

---

### 2️⃣ Create Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4️⃣ Install Nmap

Download from:
👉 https://nmap.org/download.html

✔ Make sure Nmap is added to PATH

---

### 5️⃣ Configure `.env`

Create `.env` file:

```env
VT_API_KEY=your_virustotal_key
CYBERSCAN_API_KEY=your_generated_key

GMAIL_SENDER=your_email@gmail.com
GMAIL_PASSWORD=your_app_password
GMAIL_RECIPIENT=receiver_email@gmail.com
```

---

## ▶️ Run Application

### 🔹 Start Backend

```bash
uvicorn api:app --reload
```

---

### 🔹 Start Dashboard

```bash
streamlit run dashboard/app.py
```

---

## 🌐 Usage

1. Enter target:

```
scanme.nmap.org
```

2. Click:

```
🚀 Run Scan
```

3. View:

* Risk scores
* Charts
* Services
* Recommendations
* Email report
* PDF report

---

## 📊 Example Output

| IP       | Port | Service | Risk Score | Severity    |
| -------- | ---- | ------- | ---------- | ----------- |
| 10.0.0.3 | 23   | telnet  | 10.0       | 🔴 Critical |
| 10.0.0.2 | 21   | ftp     | 6.5        | 🟠 High     |
| 10.0.0.1 | 22   | ssh     | 1.2        | 🟢 Low      |

---

## 🎯 Safe Targets for Testing

✔ scanme.nmap.org
✔ testphp.vulnweb.com
✔ localhost

❌ Do NOT scan unauthorized systems

---

## 🧠 Technologies Used

* Python
* Nmap
* VirusTotal API
* Streamlit
* FastAPI
* SQLite
* Plotly

---

## 🚀 Future Improvements

* Multi-target scanning
* CVE vulnerability detection
* AI-based risk prediction
* Real-time threat feeds

---

## ⚠️ Disclaimer

This project is for **educational purposes only**.

Do NOT scan:

* Unauthorized systems
* Government networks
* Private infrastructure without permission

---

## 👩‍💻 Author

**Sumanjali**
Cybersecurity Enthusiast | Developer


