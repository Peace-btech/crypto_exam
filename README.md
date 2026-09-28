# ETTCS801 Cryptography & Network Security Exam Project

This repository contains the practical and theoretical deliverables for the ETTCS801 Cryptography and Network Security exam.

## Repository Layout
* `toolkit.py`: Security toolkit script implementing AES-256-GCM encryption/decryption and SHA-256 integrity verification.
* `sample_students.csv`: Plaintext input dataset.
* `sample_students.enc`: AES-256-GCM encrypted output.
* `sample_students_restored.csv`: Decrypted CSV dataset for verification.
* `.gitignore`: Excludes local keys (`secret.key`) from version control.
* `risk_assessment.md`: Risk assessment and evaluation table (Question 1).
* `filter_tests.md`: Firewall configuration rules and test log (Question 3).
* `report.tex` / `report.pdf`: LaTeX technical report source and compiled document (Question 5).

## How to Run

1. Ensure Python 3.x and the `cryptography` library are installed:
   ```bash
   pip install cryptography