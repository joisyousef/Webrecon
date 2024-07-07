import os
import subprocess
import sys

def create_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def create_file(file_path):
    if not os.path.exists(file_path):
        open(file_path, 'w').close()

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Command failed: {command}\n{result.stderr}")
    return result.stdout

def main(url):
    try:
        # Create necessary directories and files
        create_dir(f"{url}/recon/scans")
        create_dir(f"{url}/recon/httprobe")
        create_dir(f"{url}/recon/potential_takeovers")
        create_dir(f"{url}/recon/wayback/params")
        create_dir(f"{url}/recon/wayback/extensions")

        create_file(f"{url}/recon/httprobe/alive.txt")
        create_file(f"{url}/recon/final.txt")
        create_file(f"{url}/recon/potential_takeovers/potential_takeovers.txt")

        print("[+] Harvesting subdomains with assetfinder...")
        assets = run_command(f"assetfinder {url}")
        with open(f"{url}/recon/final.txt", 'w') as f:
            f.write("\n".join([line for line in assets.split("\n") if url in line]))

        print("[+] Probing for alive domains...")
        alive_domains = run_command(f"cat {url}/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\\?:\\/\\///' | tr -d ':443'")
        with open(f"{url}/recon/httprobe/alive.txt", 'w') as f:
            f.write("\n".join(sorted(set(alive_domains.split("\n")))))

        print("[+] Checking for possible subdomain takeover...")
        run_command(f"subjack -w {url}/recon/final.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o {url}/recon/potential_takeovers/potential_takeovers.txt")

        print("[+] Scanning for open ports...")
        run_command(f"nmap -iL {url}/recon/httprobe/alive.txt -T4 -oA {url}/recon/scans/scanned.txt")

        print("[+] Scraping wayback data...")
        wayback_data = run_command(f"cat {url}/recon/final.txt | waybackurls")
        with open(f"{url}/recon/wayback/wayback_output.txt", 'w') as f:
            f.write("\n".join(sorted(set(wayback_data.split("\n")))))

        print("[+] Pulling and compiling all possible params found in wayback data...")
        params = run_command(f"grep '?*=' {url}/recon/wayback/wayback_output.txt | cut -d '=' -f 1 | sort -u")
        with open(f"{url}/recon/wayback/params/wayback_params.txt", 'w') as f:
            f.write(params)
        with open(f"{url}/recon/wayback/params/wayback_params.txt", 'r') as f:
            for line in f:
                print(f"{line.strip()}=")

        print("[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output...")
        with open(f"{url}/recon/wayback/wayback_output.txt", 'r') as f:
            extensions = {'js': [], 'html': [], 'json': [], 'php': [], 'aspx': []}
            for line in f:
                ext = os.path.splitext(line.strip())[1][1:]
                if ext in extensions:
                    extensions[ext].append(line.strip())

            for ext, lines in extensions.items():
                with open(f"{url}/recon/wayback/extensions/{ext}.txt", 'w') as ext_file:
                    ext_file.write("\n".join(sorted(set(lines))))

        print("[+] Cleanup temporary files...")
        for ext in extensions:
            tmp_file = f"{url}/recon/wayback/extensions/{ext}1.txt"
            if os.path.exists(tmp_file):
                os.remove(tmp_file)

        # Uncomment the following lines if you want to run EyeWitness
        # print("[+] Running EyeWitness against all compiled domains...")
        # run_command(f"python3 EyeWitness/EyeWitness.py --web -f {url}/recon/httprobe/alive.txt -d {url}/recon/eyewitness --resolve")

    except Exception as e:
        print(e)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <url>")
        sys.exit(1)
    
    main(sys.argv[1])
