# Port Scanner

A high-performance, multithreaded port scanner written in Python.  
This tool goes beyond simple port scanning by grabbing service banners, checking them against a CVE signature database, and saving results in structured formats for further analysis.

## ✨ Features
- 🚀 **Multithreaded scanning** (default: 200 threads) for speed
- 🔎 **Banner grabbing** with protocol-aware requests (HTTP, SMTP, IMAP, etc.)
- ⚠️ **CVE detection** using a local `cve_signatures.json` database
- 💾 **Persistent results** stored in both JSON and CSV
- 🔄 **Checkpointing** (resume scans from last port if interrupted)
- 🛠 **Error logging** for failed connections
- 📊 **Progress monitor** with ETA

## 📂 Output
All results are saved in the `scan_results/` folder:
- `results.json` → full structured results
- `results.csv` → easy to open in Excel/Sheets
- `checkpoint.json` → last scanned port (resume support)
- `errors.log` → connection errors & timeouts

## 🚀 Usage
```bash
python port_scanner.py
