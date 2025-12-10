# 🕵️ Malware Analysis: Malicious windows.storage.dll (DLL Hijacking Attempt)

**Source:** ANY.RUN automated sandbox  
**Analysis Date:** Nov 22, 2025  
**Sample Type:** DLL (PE32+ x64)  
**Verdict:** Malicious activity (DLL hijacking behavior)  
**Report:** [PDF](./artifacts/windows.storage_ANYRUN_Report.pdf)

---

## 🔎 1. Summary

This project documents the forensic analysis of **windows.storage.dll**, a malicious DLL masquerading as a legitimate **Windows WinRT Storage API** component. The file was executed using `regsvr32.exe`, a known "living-off-the-land" technique frequently used to sideload or register malicious DLL payloads.

ANY.RUN flagged the DLL as **malicious**, specifically identifying **DLL hijacking behavior**, a technique commonly used to:

- load malicious code under a trusted system binary  
- bypass security controls  
- gain execution under legitimate processes  

Although the DLL did not drop files or perform observable malicious operations during analysis, its **execution method alone** is traditionally associated with malware and persistence.

---

## ⚠️ 2. Key Malicious Indicators

### ✔ DLL Hijacking Attempt
The malicious DLL was executed via:

```
regsvr32.exe "C:\Users\admin\AppData\Local\Temp\windows.storage.dll"
```

`regsvr32.exe` is frequently used for:

- bypassing application whitelisting  
- executing remote payloads  
- sideloading unsigned DLLs  
- COM scriptlet executions  

ANY.RUN explicitly marks this event as:

> **MALICIOUS — DLL Hijacking**

### ✔ Masquerading as a Genuine Microsoft Component
The sample pretends to be:

```
FileDescription: Microsoft WinRT Storage API
ProductName: Microsoft® Windows® Operating System
CompanyName: Microsoft Corporation
OriginalFileName: Windows.Storage.dll
```

However:

- Signature is missing  
- Timestamp is invalid (year **2086**)  
- Execution origin (Temp folder) is abnormal  
- Loaded via `regsvr32.exe` instead of system processes  

This is a classic **masquerading technique**.

---

## 🧬 3. MITRE ATT&CK Mapping

| Behavior | ATT&CK Technique |
|----------|------------------|
| DLL sideloading / hijacking | **T1574.002 — DLL Search Order Hijacking** |
| Masquerading as legitimate DLL | **T1036 — Masquerading** |
| Execution using regsvr32 | **T1218.010 — Signed Binary Proxy Execution (regsvr32)** |
| Use of system utilities for execution | **T1218 — System Binary Proxy Execution** |
| Potential persistence methods | **T1546 — Event Triggered Execution** |

---

## 🧪 4. Technical Breakdown

### ✔ File Information (Static)
- **Type:** PE32+ DLL (x64)  
- **Size:** ~6.6MB code section  
- **SHA256:** A2B0C3C0BE9F99AEEC4310739915DDF8D09463566DA5506FA30A0776DEF6770C  
- **MD5:** 9A10131F6F32EF5356304EF6B754A9E3  
- **Subsystem:** Windows Console  
- **Timestamp:** *March 19, 2086* → Impossible & indicates tampering  
- **Language:** English (U.S.)

### ✔ Process Tree
```
explorer.exe
 └── regsvr32.exe (PID 7368)
       └── loads windows.storage.dll from Temp folder
```

- **Suspicious:** Legitimate Windows.Storage.dll should be loaded by system processes, not registered manually from a Temp path.

### ✔ Network Activity
All network traffic is associated with standard Windows Update & OCSP endpoints — no malicious C2 traffic.

→ Suggests **sample may require additional parameters or triggers** to fully execute.

### ✔ File & Registry Activity
- No file writes  
- No registry persistence  
- Behavior focused solely on **malicious execution method**

This is typical for **DLL loaders / stage-0 components**.

---

## 📁 5. Evidence & Artifacts

- **Full ANY.RUN Report:**  
  → [PDF](./artifacts/windows.storage_ANYRUN_Report.pdf)

- **Screenshots & process tree:**  
  → `/artifacts/screenshots/`

- **Indicators of Compromise (IOCs):**  
  → `/iocs/windows_storage_iocs.txt`

---

## 📌 6. Assessment

This sample exhibits strong evidence of malicious intent:

- **Executed via regsvr32.exe** (Signed Binary Proxy Execution)  
- **Masquerades as a trusted Microsoft DLL**  
- **Timestamp obfuscation** (set to 2086)  
- **Loaded from Temp folder**, not `System32\`  
- **Flagged as malicious DLL hijacking by ANY.RUN**

Although no payload execution occurred during sandboxing, this behavior aligns with:

- loader-stage malware  
- persistence DLLs  
- lateral movement footholds  
- stealthy unsigned DLL dropping during intrusion

**Final verdict:**  
### 🔥 High-confidence malicious — DLL hijacking loader

---

## 🔐 7. Recommendations

- Immediately quarantine the DLL  
- Check for persistence via:
  - Run keys  
  - Scheduled Tasks  
  - COM hijacking  
  - Services DLL entries  
- Review PowerShell logs for sideload attempts  
- Hunt for additional DLLs placed in Temp / AppData  
- Validate system integrity of:
  ```
  C:\Windows\System32\Windows.Storage.dll
  ```
- Run EDR investigation for related T1218 / T1574 activity patterns

---

## 📚 8. Skills Demonstrated

- DLL hijack analysis  
- ANY.RUN sandbox investigation  
- Static vs dynamic indicators  
- Process chain analysis  
- MITRE ATT&CK mapping  
- Threat classification  
- IOC extraction  
- Incident response documentation  
- Identifying LOLBins misuse

---

## 📝 9. Indicators of Compromise (Extracted)

See:  
📄 `./iocs/windows_storage_iocs.txt`

---

