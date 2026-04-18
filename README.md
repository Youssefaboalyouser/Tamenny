# 🛡️ Tamenny

**AI-Powered Multi-Channel Scam & Phishing Detection System**

---

## 📌 Overview

Tamenny is an intelligent security platform designed to help non-technical users detect phishing and scam messages across multiple communication channels.

It analyzes messages using a combination of:

* Technical metadata inspection
* URL and attachment analysis
* NLP-based linguistic processing
* Behavioral scam pattern detection

The system outputs:

1. ✅ A simple, user-friendly verdict
2. 🔍 A detailed technical report

---

## 🚨 Problem

Modern phishing attacks target everyday users who often:

* Cannot analyze email headers
* Fail to detect domain spoofing
* Fall for psychological manipulation
* Cannot safely inspect suspicious links or files

Existing tools are:

* Too technical
* Limited to browser extensions
* Weak in Arabic language support
* Poor at explaining results

👉 Tamenny bridges this gap.

---

## 🧠 Key Features

### 📩 Multi-Channel Support

* Email
* SMS
* WhatsApp
* Telegram

### 🔍 Technical Analysis

* SPF / DKIM / DMARC validation
* Domain spoofing detection
* URL inspection (typosquatting, redirects, TLD risk)
* Attachment analysis (macros, executables, hashes)

### 🤖 NLP & Behavioral Detection

* Detects urgency, fear, reward bait
* Identifies impersonation attempts
* Supports Arabic & English
* Classifies scam types:

  * Banking phishing
  * OTP fraud
  * Delivery scams
  * Fake investments

### 📊 Risk Scoring Engine

Weighted scoring system:

```
Final Score =
Technical Risk +
NLP Risk +
Behavioral Risk
```

| Score Range | Verdict        |
| ----------- | -------------- |
| 0 – 30      | Likely Safe    |
| 31 – 60     | Suspicious     |
| 61 – 100    | High Risk Scam |

---

## 🏗️ System Architecture

### Core Components

1. Message Ingestion Layer
2. Parsing & Normalization Engine
3. Technical Analysis Engine
4. NLP Analysis Engine
5. Risk Scoring Engine
6. Reporting Service
7. Secure Storage

---

## 🔄 User Flow

1. User receives suspicious message
2. Opens Tamenny
3. Selects message type
4. Forwards message
5. System analyzes it
6. Receives:

   * Simple verdict
   * Detailed report

---

## 📤 Output Example

### ✅ Simple Verdict

> "This message is highly suspicious. It attempts to impersonate your bank and contains a risky link."

### 🔍 Detailed Report Includes:

* Header validation results
* Domain reputation
* Extracted suspicious keywords
* Psychological indicators
* Risk breakdown

---

## ⚙️ Tech Stack

### Backend

* Python (FastAPI)

### NLP

* Transformers (BERT – multilingual / Arabic fine-tuned)

### Database

* PostgreSQL

### Frontend

* Web Based

### Threat Intelligence

* VirusTotal API
* WHOIS Lookup

### Deployment

* Docker
* Cloud (AWS / Azure / GCP)

---

## 🔐 Non-Functional Requirements

### Security

* Encrypted sessions
* Secure storage
* No data sharing without consent

### Performance

* Analysis time < 5 seconds
* Scalable architecture (microservices + queues)

### Privacy

* Auto-deletion of messages
* User-controlled data removal

---

## 🧪 Threat Model

### Potential Attacks

* API abuse
* Data poisoning
* Adversarial inputs
* System flooding

### Mitigations

* Rate limiting
* Input sanitization
* Model confidence thresholds
* Dataset filtering

---

## 🚀 Future Enhancements

* Browser extension
* Real-time SMS detection
* Crowd-sourced scam database
* Continuous ML retraining
* Enterprise dashboard
* API-as-a-Service

---

## 📈 Scalability Vision

### Phase 1

* Consumer mobile application

### Phase 2

* Public API platform

### Phase 3

* Integration with telecom providers & banks

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

---

## 📄 License

Open source grduation project from DEPI