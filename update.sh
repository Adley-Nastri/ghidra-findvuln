#!/usr/bin/env bash

echo "[+] Removing old database"
rm -f FindVuln/data/cve.db

echo "[+] Downloading new database"
wget https://github.com/Adley-Nastri/ghidra-findvuln/blob/master/FindVuln/data/cve.db

echo "[+] Installing new database"
mv cve.db FindVuln/data/cve.db

echo "[+] Done! Now you can git add the changes!"
