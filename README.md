# 🛡️ AWS S3 Audit CLI Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Boto3](https://img.shields.io/badge/Boto3-AWS-yellow?logo=amazon-aws)

Audit your AWS S3 buckets with a simple CLI tool — check for public access, encryption, versioning, and public access block settings. Export results to CSV for easy review or documentation.

---

## ⚙️ Features

- 🔐 Secure manual IAM login or AWS CLI profile support
- 📂 Lists **all S3 buckets** and audits:
  - Public Access (ACL and Bucket Policy)
  - Server-Side Encryption
  - Versioning
  - Public Access Block (PAB)
- 🧾 Exports clean CSV reports with timestamps
- ✅ Lightweight and easy to run (Python only)
- 🧠 Designed for security analysts, developers, and auditors



## 📸 Sample Output

```csv
Bucket Name,Status,Encryption,Versioning,Public Access Block
my-bucket-1,PRIVATE,ENCRYPTION ENABLED,Version Enabled,Partially Enabled
```
##🚀 Getting Started
1. Clone the repository
git clone https://github.com/ashu-nair/s3AuditingTool.git
cd s3-audit-cli-tool
2. Install dependencies
pip install -r requirements.txt
3. Run the tool
python s3_audit.py
##🔐 Authentication Modes
You will be prompted to choose:

M: Manually enter your AWS Access Key & Secret Access Key

P: Use an existing AWS profile from ~/.aws/credentials

## 📝 Requirements
Python 3.8+

IAM user with permissions to list and access S3 bucket configurations:

s3:ListAllMyBuckets

s3:GetBucketAcl

s3:GetBucketPolicy

s3:GetBucketEncryption

s3:GetBucketVersioning

s3:GetBucketPublicAccessBlock

Boto3 library

## 🗂️ Output
Each run creates a timestamped CSV report:
s3_results_YYYY-MM-DD_HH-MM-SS.csv

---

## ✅ What's Inside the Code
-AWS Session handling with boto3

-Secure credential input using getpass

-Error handling for missing policies or access

-Extensible CLI — ready for future GUI, JSON output, or multi-region support
---
## ✨ Future Improvements
-Export results to JSON

-Add GUI (e.g., Tkinter or CustomTkinter)

-Multi-region support

-Logging to file

---
