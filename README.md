SVDF - Security Vulnerability Detection Framework (starter)

Requirements:
 - Linux/WSL or macOS with python3, gcc, node/npm
 - pip install -r requirements.txt

Quick start:
1. create virtualenv & install
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

2. Run scan:
   python -m svdf.cli scan samples --out reports/report.json --iterations 300

3. View report:
   cat reports/report.json

4. View dashboard:
   cd dashboard
   npm install
   npm run start    # opens http://localhost:3000 (dev server)
   or build and serve statically with python -m http.server in dashboard/build
