# 🛰️ Advanced OSINT Platform https://husseinammr.github.io/OSINT-Platform/ للتجربه المشروع

![Status](https://img.shields.io/badge/status-active-success)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
## 🚀 Overview

This platform provides cybersecurity-focused intelligence gathering tools that help analyze and map relationships between digital entities using real-time data and visualization techniques.

## ✨ Features

- 🌐 Domain Analysis (DNS Records, Subdomains, Relationships)
- 🖥️ IP Intelligence (Reverse DNS + GeoIP Tracking 🌍)
- 📧 Email Investigation (Domain + Mail Server Detection)
- 👤 Username Tracking (Multi-platform OSINT)
- 📡 Port Scanning (Open ports + risky services)
- 📸 Image OSINT (EXIF + GPS extraction)
- 🧠 Graph-Based Analysis (Nodes & Edges)
- 🗺️ Interactive Map using Leaflet

## 🛠️ Tech Stack

- Backend: FastAPI (Python)
- Frontend: HTML, CSS, JavaScript
- Networking: socket, dns, ssl
- GeoIP API: ip-api.com
- Maps: Leaflet.js

## 📁 Project Structure

osint-platform/
│
├── main.py
├── requirements.txt
├── README.md
└── frontend/
    └── index.html

## ⚙️ Installation

1. Clone the repository:
git clone https://github.com/your-username/osint-platform.git
cd osint-platform

2. Install dependencies:
pip install -r requirements.txt

3. Run the server:
uvicorn main:app --reload

4. Open frontend:
frontend/index.html

## 📡 API Endpoints

- POST /api/v1/scan → General OSINT scan
- POST /api/v1/portscan → Port scanning
- POST /api/v1/whois → Domain analysis
- POST /api/v1/scan-image → Image analysis

## 📍 Notes

- GeoIP results are based on IP and may not be 100% accurate.
- Some features are simulated for learning purposes.

## 🎯 Use Cases

- Cybersecurity learning
- OSINT investigations
- Network analysis
- Ethical hacking practice

## ⚠️ Disclaimer

This tool is for educational and ethical use only. Do not use it for illegal activities.

