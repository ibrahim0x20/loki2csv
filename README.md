# loki2csv
Convert log files produced by loki.exe to a csv file
# How to run?
<pre>
loki2csv4.py
usage: loki2csv4.py [-h] [-d path] [-f log-file] [-v] [-s path]

options:
  -h, --help            show this help message and exit
  -d path, --csvfolder path
                        Path to Loki log files
  -f log-file           Loki log file
  -v                    Query VirusTotal (www.virustotal.com) for malware based on file hash.
  -s path, --signed path
                        Path to signed file
                      </pre>

The signed files file is generated using sigcheck from Microsoft Sysinternals and saved as a csv file.
