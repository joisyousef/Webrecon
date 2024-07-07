const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const url = process.argv[2];

const createDir = (dir) => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
};

const createFile = (file) => {
    if (!fs.existsSync(file)) {
        fs.closeSync(fs.openSync(file, 'w'));
    }
};

const runCommand = (command) => {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(`Error: ${error.message}`);
            }
            if (stderr) {
                reject(`Stderr: ${stderr}`);
            }
            resolve(stdout);
        });
    });
};

const main = async () => {
    try {
        // Create necessary directories and files
        createDir(`${url}/recon/scans`);
        createDir(`${url}/recon/httprobe`);
        createDir(`${url}/recon/potential_takeovers`);
        createDir(`${url}/recon/wayback/params`);
        createDir(`${url}/recon/wayback/extensions`);

        createFile(`${url}/recon/httprobe/alive.txt`);
        createFile(`${url}/recon/final.txt`);
        createFile(`${url}/recon/potential_takeovers/potential_takeovers.txt`);

        console.log("[+] Harvesting subdomains with assetfinder...");
        await runCommand(`assetfinder ${url} | grep ${url} >> ${url}/recon/final.txt`);

        console.log("[+] Probing for alive domains...");
        await runCommand(`cat ${url}/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\\?:\\/\\///' | tr -d ':443' | sort -u > ${url}/recon/httprobe/alive.txt`);

        console.log("[+] Checking for possible subdomain takeover...");
        await runCommand(`subjack -w ${url}/recon/final.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o ${url}/recon/potential_takeovers/potential_takeovers.txt`);

        console.log("[+] Scanning for open ports...");
        await runCommand(`nmap -iL ${url}/recon/httprobe/alive.txt -T4 -oA ${url}/recon/scans/scanned.txt`);

        console.log("[+] Scraping wayback data...");
        await runCommand(`cat ${url}/recon/final.txt | waybackurls | sort -u > ${url}/recon/wayback/wayback_output.txt`);

        console.log("[+] Pulling and compiling all possible params found in wayback data...");
        await runCommand(`grep '?*=' ${url}/recon/wayback/wayback_output.txt | cut -d '=' -f 1 | sort -u > ${url}/recon/wayback/params/wayback_params.txt`);
        const params = fs.readFileSync(`${url}/recon/wayback/params/wayback_params.txt`, 'utf8').split('\n');
        params.forEach(line => {
            if (line) console.log(`${line}=`);
        });

        console.log("[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output...");
        const waybackData = fs.readFileSync(`${url}/recon/wayback/wayback_output.txt`, 'utf8').split('\n');
        const extensions = { js: [], html: [], json: [], php: [], aspx: [] };
        waybackData.forEach(line => {
            const ext = path.extname(line).substring(1);
            if (extensions[ext]) {
                extensions[ext].push(line);
            }
        });

        for (const ext in extensions) {
            const uniqueLines = [...new Set(extensions[ext])];
            fs.writeFileSync(`${url}/recon/wayback/extensions/${ext}.txt`, uniqueLines.join('\n'));
        }

        console.log("[+] Cleanup temporary files...");
        for (const ext in extensions) {
            fs.unlinkSync(`${url}/recon/wayback/extensions/${ext}1.txt`);
        }

        // Uncomment the following lines if you want to run EyeWitness
        // console.log("[+] Running EyeWitness against all compiled domains...");
        // await runCommand(`python3 EyeWitness/EyeWitness.py --web -f ${url}/recon/httprobe/alive.txt -d ${url}/recon/eyewitness --resolve`);

    } catch (error) {
        console.error(error);
    }
};

main();
