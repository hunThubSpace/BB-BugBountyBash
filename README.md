# Custom BB (BugBounty Bash) Functions
This repository contains a collection of custom Bash functions designed to streamline and enhance the bug bounty hunting process. Each function serves a specific purpose, from gathering SSL certificate details to scanning for open ports and extracting subdomain information. By leveraging these functions, bug hunters can automate repetitive tasks, efficiently collect data, and focus more on analysis and exploitation. Explore the functions, adapt them to your workflow, and contribute to the ongoing improvement of this toolkit for the bug bounty community!

## Disclaimer
The functions in this repository are intended for educational and ethical hacking purposes only. Ensure you have permission to test any systems or applications before using these tools. The authors and contributors assume no responsibility for any misuse or illegal activity that may arise from the use of these functions. Always adhere to legal and ethical guidelines in your bug bounty hunting efforts.


## Setup Guide
To effectively utilize the functions provided in this repository, it is crucial to set up your local environment correctly. For this purpose, I highly recommend using an Ubuntu Server 22.04 VPS. This version of Ubuntu is known for its stability, security, and extensive support, making it an ideal choice for running the scripts and tools included in this repository.

1. **Operating System:**  
   This guide assumes you're using **Ubuntu Server 22.04** on a Virtual Private Server (VPS).

2. **Update & Upgrade VPS Packages:**

    ```sh
    sudo apt update && sudo apt upgrade -y
    ```

3. **Root User Preference:**  
   I prefer to operate as the **root** user, so I log into my VPS as root and avoid using `sudo` for installations and operations.

4. **Install Essential Tools:**  
   Install the minimum required tools, as some applications depend on these packages:

    ```sh
    apt install -y git vim curl zsh net-tools tmux make jq unzip postgresql-client crunch gcc python3-apt libssl-dev build-essential libpcap-dev
    ```

5. **Install pip3 (Python Package Manager):**

    ```sh
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3 get-pip.py
    rm get-pip.py
    ```

6. **Install Python Packages:**  
   Install **mmh3** and **poetry** using pip3:

    ```sh
    pip install mmh3 poetry --break-system-packages
    ```

7. **Install ZSH & Oh My Zsh:**  
   Since I use **ZSH** with **Oh My Zsh**, let's install **OMZ**:

    ```sh
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    ```

8. **Install Sourcegraph CLI (src):**  
   To use **Sourcegraph**, install the `src` CLI:

    ```sh
    curl -s -L https://sourcegraph.com/.api/src-cli/src_linux_amd64 -o /usr/local/bin/src
    chmod +x /usr/local/bin/src
    ```

9. **Install GoLang (Go):**  
   Since most applications I use are developed with **Go**, install the latest version:

    ```sh
    wget https://go.dev/dl/go1.23.1.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.23.1.linux-amd64.tar.gz
    rm go1.23.1.linux-amd64.tar.gz
    ```

    Add Go to the system's path by appending this to your `~/.zshrc`:

    ```sh
    export PATH=$PATH:/usr/local/go/bin
    ```

    Apply changes:

    ```sh
    source ~/.zshrc
    ```

    Verify the installation:

    ```sh
    go version
    ```

10. **Install Go Tools:**  
    Install additional tools using Go:

    ```sh
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
    go install -v github.com/ffuf/ffuf/v2@latest
    go install -v github.com/tomnomnom/unfurl@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/bp0lr/gauplus@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
    go install -v github.com/tomnomnom/anew@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/hakluke/hakip2host@latest
    go install -v github.com/d3mondev/puredns/v2@latest
    ```

    Add the Go binary path to your `~/.zshrc`:

    ```sh
    export PATH=$PATH:/root/go/bin
    ```

    Apply changes:

    ```sh
    source ~/.zshrc
    ```

11. **Install Other Tools (Massdns, Dnsgen, Altdns, Masscan):**

    ```sh
    mkdir -p /opt/{others,wordlists}
    ```

    Add the `/opt/others` directory to the system path by adding the following to your `~/.zshrc`:

    ```sh
    export PATH=$PATH:/opt/others
    ```

    Apply changes:

    ```sh
    source ~/.zshrc
    ```

    - **Massdns:**

      ```sh
      cd /opt/others
      git clone https://github.com/blechschmidt/massdns.git massdns_dic
      cd massdns_dic
      make
      make install
      mv bin/massdns /opt/others
      rm -rf ../massdns_dic
      ```

    - **Dnsgen:**

      ```sh
      python3 -m pip install dnsgen --break-system-packages
      ```

    - **Altdns:**

      ```sh
      pip3 install py-altdns --break-system-packages
      ```

    - **Masscan:**

      ```sh
      cd /opt/others
      git clone https://github.com/robertdavidgraham/masscan masscan_dic
      cd masscan_dic
      make
      make install
      mv bin/masscan /opt/others
      rm -rf ../masscan_dic
      ```

12. **Update `~/.zshrc`:**  
    Replace your **~/.zshrc** file with the following content:

    ```sh
    export ZSH="$HOME/.oh-my-zsh"
    ZSH_THEME="robbyrussell"
    plugins=(git)
    source $ZSH/oh-my-zsh.sh

    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:/root/go/bin
    export PATH=$PATH:/opt/others
    ```

13. **Apply `~/.zshrc` Changes:**  
    Save the file and apply the changes:

    ```sh
    source ~/.zshrc
    ```
---

## Custom Bash (ZSH) Functions
### 1. **`bb_get_cert_details`**  
Retrieves and displays detailed certificate information for a given domain or list of domains using OpenSSL.

```sh
bb_get_cert_details() {
    if [[ $# -eq 1 ]]; then
        input="$1"
        echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text 2> /dev/null
    else
        while read -r input; do
            echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text 2> /dev/null
        done
    fi
}
```

| Syntax                                  | Description            |
|------------------------------------------|------------------------|
| `echo IP:443 \| bb_get_cert_details`     | Input via stdin        |
| `bb_get_cert_details IP:443`            | Argument input         |
| `cat ips.txt \| bb_get_cert_details`     | File input             |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image.png)
</details>

---

### 2. **`bb_get_cert_brief`**  
Extracts and summarizes issuer, subject, and DNS information from SSL certificates for specified domains.

```sh
bb_get_cert_brief() {
    if [[ $# -eq 1 ]]; then
        input="$1"
        echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text \
        | grep -E "(Issuer|Subject:|DNS:)" | grep -vE "(Issuers)" | sed "s/ //g"
    else
        while read -r input; do
            echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text \
            | grep -E "(Issuer|Subject:|DNS:)" | grep -vE "(Issuers)" | sed "s/ //g"
        done
    fi
}
```

| Syntax                                  | Description            |
|------------------------------------------|------------------------|
| `echo IP:443 \| bb_get_cert_brief`       | Input via stdin        |
| `bb_get_cert_brief IP:443`              | Argument input         |
| `cat ips.txt \| bb_get_cert_brief`       | File input             |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-1.png)
</details>

---

### 3. **`bb_get_cert_subdomain`**  
Lists unique subdomains found in the DNS fields of SSL certificates for a given domain or list.

```sh
bb_get_cert_subdomain() {
    if [[ $# -eq 1 ]]; then
        input="$1"
        echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text 2> /dev/null \
        | grep "DNS:" | grep -v "Issuers" | sed "s/ //g" | sed "s/,/\n/g" | tr -d "DNS:" | sed "s/*.//g" | sort -u
    else
        rm -rf .tmp
        while read -r input; do
            echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text 2> /dev/null \
            | grep "DNS:" | grep -v "Issuers" | sed "s/ //g" | sed "s/,/\n/g" | tr -d "DNS:" | sed "s/*.//g" >> .tmp
        done
        cat .tmp | sort -u; rm -rf .tmp
    fi
}
```

| Syntax                                  | Description            |
|------------------------------------------|------------------------|
| `echo IP:443 \| bb_get_cert_subdomain`   | Input via stdin        |
| `bb_get_cert_subdomain IP:443`          | Argument input         |
| `cat ips.txt \| bb_get_cert_subdomain`   | File input             |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-2.png)
</details>

---

### 4. **`bb_email2domain_viewdns`**  
Searches for domains associated with an email address using the ViewDNS service.

```sh
bb_email2domain_viewdns() {
    cf_clearance="<INSERT_COOKIE>"
    useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    if [[ $# -eq 1 ]]; then
        input="$1"
        curl "https://viewdns.info/reversewhois/?q=$input" -H "cookie: cf_clearance=$cf_clearance" -H "user-agent: $useragent" 2> /dev/null \
        | grep -oE "<tr>(.+)</tr>" | sed -E "s_(<tr>|</tr>)_\n_g" | grep -E "^(<td>\w+)" | grep -v "Domain Name" | cut -d ">" -f 2 | cut -d "<" -f 1 | sort -u
    else
        rm -rf .tmp
        while read -r input; do
            curl "https://viewdns.info/reversewhois/?q=$input" -H "cookie: cf_clearance=$cf_clearance" -H "user-agent: $useragent" 2> /dev/null \
            | grep -oE "<tr>(.+)</tr>" | sed -E "s_(<tr>|</tr>)_\n_g" | grep -E "^(<td>\w+)" | grep -v "Domain Name" | cut -d ">" -f 2 | cut -d "<" -f 1 >> .tmp
        done
        cat .tmp | sort -u; rm -rf .tmp
    fi
}
```

| Syntax                                  | Description            |
|------------------------------------------|------------------------|
| `echo email \| bb_email2domain_viewdns`  | Input via stdin        |
| `bb_email2domain_viewdns email`         | Argument input         |
| `cat emails.txt \| bb_email2domain_viewdns` | File input         |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-3.png)
</details>

---

### 5. **`bb_subdomain_dns_rapiddns`**  
Fetches and lists unique subdomains for a specified domain using the RapidDNS service.

```sh
bb_subdomain_dns_rapiddns() {
    if [[ $# -eq 1 ]]; then
        input="$1"
        curl -s "https://rapiddns.io/subdomain/$input?full=1" | grep -Eo '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | grep "$input" | sort -u
    else
        while read -r input; do
            curl -s "https://rapiddns.io/subdomain/$input?full=1" | grep -Eo '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | grep "$input" | sort -u
        done
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `bb_subdomain_dns_rapiddns tesla.com`     | Argument input         |
| `echo tesla.com \| bb_subdomain_dns_rapiddns` | Input via stdin    |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-4.png)
</details>

---

### 6. **`bb_cidr_remove_cdn`**
Removes CDN IP addresses from a list of CIDR notations using the `mapcidr` and `cdncheck` tools.

```sh
bb_cidr_remove_cdn() {
    input=$(cat)
    if [[ -f "$input" ]]; then
        cat "$input" | mapcidr -silent | cdncheck -silent -e
    else
        echo "$input" | mapcidr -silent | cdncheck -silent -e
    fi
}
```

| Syntax | Description |
|-------------------------------------------|------------------------|
| `echo 135.181.255.10 \| bb_cidr_remove_cdn` | STDIN, Single IP |
| `echo 135.181.255.0/30 \| bb_cidr_remove_cdn` | STDIN, CIDR |
| `cat cidr.txt \| bb_cidr_remove_cdn` | File including Single IP and CIDR |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-5.png)
</details>

---

### 7. **`bb_asn2cidr_details`**
Retrieves and formats details about IPv4 prefixes associated with a specified ASN using the BGPView API.

```sh
bb_asn2cidr_details() {
    if [[ $# -eq 1 ]]; then
        input="$1"
        curl -s "https://api.bgpview.io/asn/$input/prefixes" \
        | jq -r '["Prefix", "Name", "Description", "Country Code"], (.data.ipv4_prefixes[] | [.prefix, .name, (.description // "N/A"), .country_code]) | @tsv' 2> /dev/null \
        | awk -F'\t' '{printf "%-24s %-40s %-50s %s\n", $1, $2, $3, $4}'
    else
        printf "%-24s %-40s %-50s %s\n" "Prefix" "Name" "Description" "Country Code"
        while read -r input; do
            curl -s "https://api.bgpview.io/asn/$input/prefixes" \
            | jq -r '(.data.ipv4_prefixes[] | [.prefix, .name, (.description // "N/A"), .country_code]) | @tsv' 2> /dev/null \
            | awk -F'\t' '{printf "%-24s %-40s %-50s %s\n", $1, $2, $3, $4}'
        done
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo AS12348 \| bb_asn2cidr_details` | STDIN, Single ASN (With AS Prefix) |
| `echo 12348 \| bb_asn2cidr_details` | STDIN, Single ASN (With AS Prefix) |
| `cat ASNs.txt \| bb_asn2cidr_details` | File including Multiple ASN |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-6.png)
</details>

---

### 8. **`bb_asn2cidr`**
Lists all IPv4 prefixes associated with a specified ASN using the BGPView API.

```sh
bb_asn2cidr() {
    if [[ $# -eq 1 ]]; then
        input="$1"
        curl -s "https://api.bgpview.io/asn/$input/prefixes" | jq -r ".data.ipv4_prefixes[].prefix" 2> /dedv/null
    else
        while read -r input; do
            curl -s "https://api.bgpview.io/asn/$input/prefixes" | jq -r ".data.ipv4_prefixes[].prefix" 2> /dedv/null
        done
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo AS12348 \| bb_asn2cidr` | STDIN, Single ASN (With AS Prefix) |
| `echo 12348 \| bb_asn2cidr` | STDIN, Single ASN (With AS Prefix) |
| `cat ASNs.txt \| bb_asn2cidr` | File including Multiple ASN |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-7.png)
</details>

---

### 9. **`bb_ipcidr2asn_details`**
Displays ASN details, including IP and registry information, for a specified CIDR block using the Cymru WHOIS service.

```sh
bb_ipcidr2asn_details() {
    printf "%-7s | %-16s | %-19s | %-2s | %-8s | %-10s | %-20s\n" "ASN" "IP" "BGP Prefix" "CC" "Registry" "Allocated" "AS Name"
    if [[ $# -eq 1 ]]; then
        input="$1"
        whois -h whois.cymru.com -v $input | grep -vE "Warning| BGP Prefix"
    else
        input=$(cat);
        whois -h whois.cymru.com -v $input | grep -vE "Warning| BGP Prefix"
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo 157.240.2.20 \| bb_ipcidr2asn_details` | STDIN, Single IP |
| `bb_ipcidr2asn_details 157.240.2.20` | Argument, Single IP |
| `cat ips.txt \| bb_ipcidr2asn_details` | File including Multiple IP address |
| `cat mix.txt \| bb_ipcidr2asn_details` | File including IPs and CIDR |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-8.png)
</details>

---

### 10. **`bb_ipcidr2asn`**
Retrieves the ASN for a specified CIDR block using the Cymru WHOIS service.

```sh
bb_ipcidr2asn() {
    if [[ $# -eq 1 ]]; then
        input="$1"
        whois -h whois.cymru.com -v $input | grep -vE "Warning| BGP Prefix" | cut -d " " -f 1
    else
        while read -r input; do
            whois -h whois.cymru.com -v $input | grep -vE "Warning| BGP Prefix" | cut -d " " -f 1 >> .tmp
        done
        cat .tmp | sort -u; rm -rf .tmp
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo 157.240.2.20 \| bb_ipcidr2asn` | STDIN, Single IP |
| `bb_ipcidr2asn 157.240.2.20` | Argument, Single IP |
| `cat ips.txt \| bb_ipcidr2asn` | File including Multiple IP address |
| `cat cidrs.txt \| bb_ipcidr2asn` | File including Multiple CIDRs |
| `cat mix.txt \| bb_ipcidr2asn` | File including IPs and CIDR |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-9.png)
</details>

---

### 11. **`bb_ipscan_naabu`**
Scans a specified CIDR for open ports using the `naabu` tool.

```sh
bb_ipscan_naabu(){
    $ports="80,8000,8080,8880,2052,2082,2086,2095,443,2053,2083,2087,2096,8443,10443"
    if [[ $# -eq 1 ]]; then
        input="$1"
        echo $input | mapcidr -silent | naabu -p "$ports" -silent
    else
        input=$(cat)
        if [[ -f "$input" ]]; then
            cat "$input" | mapcidr -silent | naabu -p "$ports" -silent
        else
            echo "$input" | mapcidr -silent | naabu -p "$ports" -silent
        fi
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo 103.49.13.0/29 \| bb_ipscan_naabu` | STDIN, CIDR or Single IP |
| `bb_ipscan_naabu 103.49.13.0/29` | Argument, CIDR or Single IP |
| `cat cidrs.txtt \| bb_ipscan_naabu` | File including Multiple CIDRs |
| `cat cidrs.txt \| bb_ipscan_naabu \| bb_get_cert_subdomain` | Extracted Subdomains from SSL certifications |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-10.png)
</details>

---

### 12. **`bb_ipscan_masscan`**
Scans a specified CIDR for open ports using the `masscan` tool.

```sh
bb_ipscan_masscan(){
    ports="80,8000,8080,8880,2052,2082,2086,2095,443,2053,2083,2087,2096,8443,10443"
    if [[ $# -eq 1 ]]; then
        input="$1"
        masscan $input --open --ports "$ports" 2> /dev/null | grep "open" | awk '{print $6 ":" $4}' | cut -d "/" -f 1
    else
        input=$(cat)
        if [[ -f "$input" ]]; then
            masscan $input --open --ports "$ports" 2> /dev/null | grep "open" | awk '{print $6 ":" $4}' | cut -d "/" -f 1   
        else
            masscan $input --open --ports "$ports" 2> /dev/null | grep "open" | awk '{print $6 ":" $4}' | cut -d "/" -f 1
        fi
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo 103.49.13.0/29 \| bb_ipscan_masscan` | STDIN, CIDR or Single IP |
| `bb_ipscan_masscan 103.49.13.0/29` | Argument, CIDR or Single IP |
| `cat cidrs.txtt \| bb_ipscan_masscan` | File including Multiple CIDRs |
| `cat cidrs.txt \| bb_ipscan_masscan \| bb_get_cert_subdomain` | Extracted Subdomains from SSL certifications |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-11.png)
</details>

---
### 13. **`bb_get_ptr`**
Retrieves and lists PTR records for a given IP address or list of IPs.

```sh
bb_get_ptr(){
    if [[ $# -eq 1 ]]; then
        input="$1"
        echo $input | mapcidr -silent | dnsx -silent -resp-only -ptr | sort -u 
    else
        input=$(cat)
        if [[ -f "$input" ]]; then
            cat $input | mapcidr -silent | dnsx -silent -resp-only -ptr | sort -u
        else
            echo $input | mapcidr -silent | dnsx -silent -resp-only -ptr | sort -u		
        fi
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo 19.12.18.0/24 \| bb_get_ptr` | STDIN, CIDR or Single IP |
| `bb_get_ptr 19.12.18.0/24` | Argument, CIDR or Single IP |
| `cat cidrs.txt \| bb_get_ptr` | File including Multiple CIDRs |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-12.png)
</details>

---
### 14. **`bb_get_ptr_cert`**
Fetches PTR records linked to IP addresses and filters results to show associated certificates.

```sh
bb_get_ptr_cert(){
    if [[ $# -eq 1 ]]; then
        input="$1"
        echo $input | mapcidr -silent | hakip2host | cut -d " " -f 3 | sort -u
    else
        input=$(cat)
        if [[ -f "$input" ]]; then
            cat $input | mapcidr -silent | hakip2host | cut -d " " -f 3 | sort -u
        else
            echo $input | mapcidr -silent | hakip2host | cut -d " " -f 3 | sort -u
        fi
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo 19.12.18.0/24 \| bb_get_ptr_cert` | STDIN, CIDR or Single IP |
| `bb_get_ptr_cert 19.12.18.0/24` | Argument, CIDR or Single IP |
| `cat cidrs.txt \| bb_get_ptr_cert` | File including Multiple CIDRs |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-13.png)
</details>

---
### 15. **`bb_crtsh_subdomain`**
Queries the crt.sh database to retrieve unique subdomains associated with a specified domain.

```sh
bb_crtsh_subdomain() {
    if [ -z "$1" ]; then read -r domain; else domain="$1"; fi
    query=$(cat <<-END
        SELECT ci.NAME_VALUE FROM certificate_and_identities ci WHERE plainto_tsquery('certwatch', '$domain') @@ identities(ci.CERTIFICATE)
END
)
    result=$(echo "$query" | psql -t -h crt.sh -p 5432 -U guest certwatch 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "$result" | sed 's/ //g' | egrep ".*.\.$domain" | sed 's/*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u
    else
        echo "Failed to execute query or connect to the crt.sh database."
    fi
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo tesla.com \| bb_crtsh_subdomain` | STDIN, Domain |
| `bb_crtsh_subdomain tesla.com` | Argument, Domain |
| `cat domains.txt \| bb_crtsh_subdomain` | File including Multiple Domains |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-14.png)
</details>

---
### 16. **`bb_abuseipdb_subdomain`**
Extracts potential subdomains for an IP address using the AbuseIPDB service.

```sh
bb_abuseipdb_subdomain(){
    abuseIPDB_cookie="cookie: abuseipdb_session=<INSERT YOUR COOKIE HERE>"
    abuseIPDB_user_agent="user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
    if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
    curl -s "https://www.abuseipdb.com/whois/$input" -H "$abuseIPDB_cookie" -H "$abuseIPDB_user_agent" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e "s/$/.$input/"
    unset abuseIPDB_cookie; unset abuseIPDB_user_agent
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo tesla.com \| bb_abuseipdb_subdomain` | STDIN, Domain |
| `bb_abuseipdb_subdomain tesla.com` | Argument, Domain |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-15.png)
</details>

---
### 17. **`bb_chaos_search`**
Searches for URLs related to a specified keyword from the Chaos Data repository.

```sh
bb_chaos_search() {
    if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
    curl -s "https://chaos-data.projectdiscovery.io/index.json" | jq ".[].URL" --raw-output | grep $input
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo tesla \| bb_chaos_search` | STDIN, Company name |
| `bb_chaos_search tesla` | Argument, Company name |
| `cat programs.txt \| bb_chaos_search` | STDIN, A file contains companies name |
| `echo "-e \*.\*" \| bb_chaos_search` | STDIN, Search for all programs |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-16.png)
</details>

---
### 18. **`bb_chaos_download`**
Downloads and extracts data from URLs associated with a specified keyword from the Chaos Data repository.

```sh
bb_chaos_download() {
    rm -rf chaos; mkdir -p chaos; cd chaos
    if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
    curl -s "https://chaos-data.projectdiscovery.io/index.json" | jq ".[].URL" --raw-output | grep $input > .tmp
    for link in $(cat .tmp); do wget -nv "$link"; done
    for file in $(ls); do unzip -qq $file 2> /dev/null; done; rm -rf *.zip; rm -rf .tmp; cd - 2> /dev/null
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo tesla \| bb_chaos_download` | STDIN, Company name |
| `bb_chaos_download tesla` | Argument, Company name |
| `cat programs.txt \| bb_chaos_download` | STDIN, A file contains companies name |
| `echo "-e \*.\*" \| bb_chaos_download` | STDIN, All subdomains for all companies |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-17.png)
</details>

---
### 19. **`bb_github_subdomain`**
Searches for subdomains related to a specified domain using the Sourcegraph search API.

```sh
bb_github_subdomain(){
    export SRC_ENDPOINT=https://sourcegraph.com
    export SRC_ACCESS_TOKEN=<INSERT-SRC-ACCESS-TOKEN-HERE>
    if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
    q=$(echo $input | sed -e 's/\./\\\./g')
    src search -json '([a-z\-]+)?:?(\/\/)?([a-zA-Z0-9]+[.])+('${q}') count:5000 fork=yes archive:yes' \
    | jq -r '.Results[] | .lineMatches[].preview, .file.path' | grep -oiE '([a-zA-Z0-9]+[.])+('${q}')' | awk '{print to lower($0)}' | sort -u
    unset SRC_ENDPOINT; unset SRC_ACCESS_TOKEN
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo tesla.com \| bb_github_subdomain` | STDIN, Domain |
| `bb_github_subdomain tesla.com` | Argument, Domain |
---
### 20. **`bb_wlgen_assetnote`**
Merges and generates a unique wordlist of DNS and subdomain entries from Assetnote.

```sh
bb_wlgen_assetnote() {
    cd /opt/wordlists/
    wget -nv https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
    wget -nv https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt
    cat best-dns-wordlist.txt 2m-subdomains.txt | tr '[:upper:]' '[:lower:]' | sort -u > static_assetnote_merged.txt
    rm -rf best-dns-wordlist.txt 2m-subdomains.txt; cd - 2> /dev/null
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `bb_wlgen_assetnote` | Just type the function, result saved in **/opt/wordlists/static_assetnote_merged.txt** |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-18.png)
</details>

---
### 21. **`bb_wlgen_4char`**
Generates a wordlist of all combinations of 1 to 4 characters using `crunch`.

```sh
bb_wlgen_4char() {
    crunch 1 4 abcdefghijklmnopqrstuvwxyz1234567890 > /opt/wordlists/static_4_characters.txt
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `bb_wlgen_4char` | Just type the function, result saved in **/opt/wordlists/static_4_characters.txt** |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-19.png)
</details>

---
### 22. **`bb_wlgen_chaos`**
Creates a unique wordlist from subdomains found in the Chaos Data repository.

```sh
bb_wlgen_chaos() {
    cd /opt/wordlists 
    echo "-e *.*" | bb_chaos_download; rm -rf *.zip.1
    cat chaos/* | cut -d "." -f 1 | sort -u | grep -v -E "\*" | grep -v -E "\_" > static_chaos.txt; rm -rf /opt/wordlists/chaos; cd ~
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `bb_wlgen_chaos` | Just type the function, result saved in **/opt/wordlists/static_chaos.txt** |


<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-20.png)
</details>

---
### 23. **`bb_wlgen_dynamic`**
Merges and generates a dynamic wordlist from specified DNS-related files hosted on GitHub.

```sh
bb_wlgen_dynamic() {
    cd /opt/wordlists/
    wget -nv https://raw.githubusercontent.com/AlephNullSK/dnsgen/master/dnsgen/words.txt
    wget -nv https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt
    cat words.txt words.txt.1 | sort -u > dynamic_dnsgalt.txt; rm words.txt words.txt.1; cd - > /dev/null
}
```
| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `bb_wlgen_dynamic` | Just type the function, result saved in **/opt/wordlists/dynamic_dnsgalt.txt** |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-21.png)
</details>

---
### 24. **`bb_dns_static`**
Resolves DNS records for a specified domain or list of domains and outputs the results.

```sh
bb_dns_static() {
    if [[ "$1" == "-" ]]; then input=$(cat); else input="$1"; fi
    puredns resolve $2 --rate-limit 800 -w dns_static.txt
    #shuffledns -silent -d "$input" -mode resolve -list "$2" -r ~/.resolvers -m massdns -o dns_static.txt
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `echo tesla.com \| bb_dns_static - static_wordlist.txt` | STDIN, Needs domain, static_wordlist |
| `bb_dns_static tesla.com wordlist.txt` | Argument, Needs domain, static_wordlist |

---
### 25. **`bb_dns_dynamic_dnsgen`**
Generates dynamic DNS records using `dnsgen` and resolves them for a specified domain.

```sh
bb_dns_dynamic_dnsgen() {
    if [[ "$1" == "-" ]]; then input=$(cat); else input="$1"; fi
    dnsgen "$input" -w "$3" | shuffledns -d "$2" -mode resolve -r ~/.resolvers -m massdns -o dns_dynamic.txt
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `bb_dns_dynamic_dnsgen [subdomains-list] [domain] [wordlist]` | Argument, Needs domain, dynamic_wordlist and Subdomain_list (Resolved) |

---
### 26. **`bb_dns_dynamic_altdns`**
Generates potential subdomains using `altdns`, resolves them, and outputs the results.

```sh
bb_dns_dynamic_altdns() {
    if [[ "$1" == "-" ]]; then input=$(cat); echo "$input" > temp_input.txt; \
    altdns -i temp_input.txt -o temp_output.txt -w "$3"; else altdns -i "$1" -o temp_output.txt -w "$3"; fi
    shuffledns -d "$2" -mode resolve -r ~/.resolvers -m massdns -o dns_dynamic.txt < temp_output.txt
    rm -f temp_input.txt temp_output.txt
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `bb_dns_dynamic_altdns [subdomains-list] [domain] [wordlist]` | Argument, Needs domain, dynamic_wordlist and Subdomain_list (Resolved) |

---
### 27. **`bb_livesubs_httpx`**
Performs HTTP requests to gather status and technical details for specified URLs using `httpx`.

```sh
bb_livesubs_httpx() {
    if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
    echo "$input" | httpx -silent -follow-host-redirects -title -status-code -cdn -tech-detect \
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15" -threads 1
    #-H "Referer: https://$input"
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `google.com \| bb_livesubs_httpx` | STDIN, Domain or Subdomain |
| `bb_livesubs_httpx google.com` | Argument, Domain or Subdomain |
| `echo subs.txt \| bb_livesubs_httpx` | File, list of subdomains |

<details>
<summary>Click to expand/collapse image</summary>

![Image](Images/image-22.png)
</details>

---
### 28. **`bb_livesubs_httpx`**
Extract subdomains from historical Internet Archive (WaybackURL)

```sh
bb_gau_subs() {
    if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
    gauplus -subs $input -random-agent | sed "s/\^M//g" | sed "s/\*.//g" | sed -E "s/^\.//g" | cut -d / -f3 | cut -d : -f 1 | sort -u
}
```

| Syntax                                   | Description            |
|-------------------------------------------|------------------------|
| `google.com \| bb_gau_subs` | STDIN, Domain or Subdomain |
| `bb_gau_subs google.com` | Argument, Domain or Subdomain |



## Contributing

We welcome contributions from the community! Whether you have ideas for new functions, improvements to existing ones, or documentation enhancements, your input is valuable. Please fork the repository, make your changes, and submit a pull request. Let's work together to make this toolkit even more powerful and useful for all bug bounty hunters!

Thank you for your interest in contributing!
