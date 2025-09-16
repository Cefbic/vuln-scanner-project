# 🔎 Vulnerability Scanner Project  

This project was completed as part of my Master’s degree in Cybersecurity. It demonstrates a vulnerability assessment workflow using a customized open-source Python scanner tested against a deliberately vulnerable web application (DVWA) in a controlled lab environment.  

---

## 🔧 Project Overview  

**Objectives:**  
- Deploy a vulnerable web application for security testing  
- Customize and enhance an open-source vulnerability scanner  
- Run scans to detect vulnerabilities and generate a report 
- Analyze findings to assess risk severity  

<p align="center">
  <img src="images/Project_Chart.png" alt="Scanner Running" width="70%" />
</p>  

---

## 🔄 Vulnerability Management Lifecycle (Project Context)  

The standard vulnerability management lifecycle includes five phases:  

1. **Discover** – Identify assets and vulnerabilities  
2. **Assess** – Analyze and validate findings  
3. **Prioritize** – Rank vulnerabilities by severity and impact  
4. **Report** – Communicate findings to stakeholders  
5. **Remediate** – Apply fixes and mitigations  

**Implemented in this project:**  
- ✅ **Discover:** Deployed DVWA and scanned with a Python-based scanner  
- ✅ **Assess:** Analyzed detected vulnerabilities from scan results  
- ⚠️ **Prioritize:** Not fully covered (no CVSS scoring or asset criticality ranking)  
- ✅ **Report:** Generated automated reports via the scanner  
- ❌ **Remediate:** Not in scope (no patches or configuration changes applied)  

📌 *Future improvement:* Add prioritization (e.g., CVSS scoring) and remediation testing to complete the lifecycle.  

<p align="center">
  <img src="images/Vulnerability_Management_Lifecycle.png" alt="Vulnerability Management Lifecycle" width="70%" />
</p>  

---

## 🖥️ Lab Setup  

1. **DVWA Deployment**  
   - Cloned DVWA repository into `/var/www/html` using `git clone`  
   - Configured `config.inc.php` with MariaDB connection details  
   - Started **MariaDB** and **Apache2** services  
   - Created DVWA database with proper privileges  

<p align="center">
  <img src="images/DVWA%201.jpg" alt="DVWA Step 1" width="70%" />
</p>  

<p align="center">
  <img src="images/DVWA%202.jpg" alt="DVWA Step 2" width="70%" />
</p>  

<p align="center">
  <img src="images/DVWA%204.jpg" alt="DVWA Step 4" width="70%" />
</p>  

<p align="center">
  <img src="images/DVWA%205.jpg" alt="DVWA Step 5" width="70%" />
</p>  

<p align="center">
  <img src="images/DVWA.jpg" alt="DVWA Running" width="70%" />
</p>  

2. **Scanner Execution**  
   - Launched custom Python scanner (`securetask.py`) targeting DVWA web server  
   - Provided feedback during execution (threat level, definitions, remediation hints)  
   - Generated summary reports of vulnerabilities detected vs. skipped  

<p align="center">
  <img src="images/Running%20Command.jpg" alt="Running Command" width="70%" />
</p>  

<p align="center">
  <img src="images/Scanner%20running.jpg" alt="Scanner Running" width="70%" />
</p>  

<p align="center">
  <img src="images/Scanner%20feedback.jpg" alt="Scanner Feedback" width="70%" />
</p>  

<p align="center">
  <img src="images/Scanner%20results.jpg" alt="Scanner Results" width="70%" />
</p>  

---

## 📊 Results  

- Successfully identified multiple vulnerabilities in the DVWA test environment  
- Scanner output included:  
  - Threat level classification  
  - Suggested remediation steps  
  - Summary report of findings  

---

## 🚀 Key Takeaways  

- Hands-on experience with the **vulnerability management lifecycle**  
- Practical exposure to:  
  - Linux administration (Apache2, MariaDB)  
  - Vulnerability scanning tools & reporting  
  - Web application security testing using DVWA  
- Foundation for extending to prioritization (CVSS) and remediation testing  

---

## 📂 Repository Structure  

- `/images` → Supporting screenshots  
- `securetask.py` → Vulnerability scanner script  
- `README.md` → Project documentation  

---

## 🔗 References  

- [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)  
- Vulnerability Management lifecycle best practices (NIST, CIS)  
