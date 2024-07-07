#!/bin/bash

set -euo pipefail

create_dir() {
    local dir=$1
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
    fi
}

create_file() {
    local file=$1
    if [ ! -f "$file" ]; then
        touch "$file"
    fi
}

url=$1

# Create necessary directories and files
create_dir "$url/recon/scans"
create_dir "$url/recon/httprobe"
create_dir "$url/recon/potential_takeovers"
create_dir "$url/recon/wayback/params"
create_dir "$url/recon/wayback/extensions"

create_file "$url/recon/httprobe/alive.txt"
create_file "$url/recon/final.txt"
create_file "$url/recon/potential_takeovers/potential_takeovers.txt"

echo "[+] Harvesting subdomains with assetfinder..."
assetfinder "$url" | grep "$1" >> "$url/recon/final.txt"

echo "[+] Probing for alive domains..."
cat "$url/recon/final.txt" | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' | sort -u > "$url/recon/httprobe/alive.txt"

echo "[+] Checking for possible subdomain takeover..."
subjack -w "$url/recon/final.txt" -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o "$url/recon/potential_takeovers/potential_takeovers.txt"

echo "[+] Scanning for open ports..."
nmap -iL "$url/recon/httprobe/alive.txt" -T4 -oA "$url/recon/scans/scanned.txt"

echo "[+] Scraping wayback data..."
cat "$url/recon/final.txt" | waybackurls | sort -u > "$url/recon/wayback/wayback_output.txt"

echo "[+] Pulling and compiling all possible params found in wayback data..."
grep '?*=' "$url/recon/wayback/wayback_output.txt" | cut -d '=' -f 1 | sort -u > "$url/recon/wayback/params/wayback_params.txt"
for line in $(cat "$url/recon/wayback/params/wayback_params.txt"); do
    echo "$line="
done

echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
while read -r line; do
    ext="${line##*.}"
    case "$ext" in
        js) echo "$line" >> "$url/recon/wayback/extensions/js.txt" ;;
        html) echo "$line" >> "$url/recon/wayback/extensions/jsp.txt" ;;
        json) echo "$line" >> "$url/recon/wayback/extensions/json.txt" ;;
        php) echo "$line" >> "$url/recon/wayback/extensions/php.txt" ;;
        aspx) echo "$line" >> "$url/recon/wayback/extensions/aspx.txt" ;;
    esac
done < "$url/recon/wayback/wayback_output.txt"

echo "[+] Sorting extension files..."
for ext in js jsp json php aspx; do
    sort -u "$url/recon/wayback/extensions/$ext.txt" -o "$url/recon/wayback/extensions/$ext.txt"
done

echo "[+] Cleanup temporary files..."
rm -f "$url/recon/wayback/extensions/"*.tmp

# Uncomment the following lines if you want to run EyeWitness
# echo "[+] Running EyeWitness against all compiled domains..."
# python3 EyeWitness/EyeWitness.py --web -f "$url/recon/httprobe/alive.txt" -d "$url/recon/eyewitness" --resolve
