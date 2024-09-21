# BB_Functions
For using this functions, you should install the requirements.
1. Ubuntu Server 22.04; use virtual private server (VPS)
2. Upgrade your VPS

   ```sh
    sudo apt update
    sudo apt upgrade -y
    ```
3. I prefer to use from **root** user, so I login to my VPS as a root user and do not use **sudo** keyboard for installing or any operation on it. 
4. Install the minimum tools; some apps need to it

    ```sh
    apt install -y git vim curl zsh net-tools tmux make zsh jq unzip postgresql-client crunch gcc python3-aptpython3-distutils libssl-dev build-essential libpcap-dev 
    ```

5. Install the pip3 (python package manager)

    ```sh
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py; python3 get-pip.py; rm get-pip.py
    ```

6. Install **mmh3** and **poetry** (Python packages)

    ```sh
    pip install mmh3 poetry
    ```

7. I use **ZSH** and **oh-my-zsh**, so let's installing the **OMZ**

    ```sh
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    ```

8. Install **src** for using **Sourcegraph**

    ```sh
    curl -s -L https://sourcegraph.com/.api/src-cli/src_linux_amd64 -o /usr/local/bin/src; chmod +x /usr/local/bin/src
    ```

9. Most of applications are developed by **GoLang**; so let's install the last version of GoLang

    ```sh
    wget https://go.dev/dl/go1.23.1.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.1.linux-amd64.tar.gz
    rm go1.23.1.linux-amd64.tar.gz

    ## add `export PATH=$PATH:/usr/local/go/bin` to ~/.zshrc
    source ~/.zshrc

    # Verify > go version
    ```

10. Install tools (GoLang tools)

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

    ## add `export PATH=$PATH:/root/go/bin` to ~/.zshrc
    source ~/.zshrc
    ```

11. Install another tools; **massdns**, **dnsgen**, **altdns** and **masscan**

    ```sh
    mkdir -p /opt/{others,wordlists}
    ## add `export PATH=$PATH:/opt/others` to ~/.zshrc
    source ~/.zshrc

    # Massdns
    cd /opt/others
    git clone https://github.com/blechschmidt/massdns.git massdns_dic
    cd massdns_dic; make; make install
    mv bin/massdns /opt/others; rm -rf ../massdns_dic; cd ~

    # DNSGen
    python3 -m pip install dnsgen
    ## Location > /usr/local/bin/dnsgen

    # altdns
    pip3 install py-altdns
    ## Location > /usr/local/bin/altdns

    # Masscan
    cd /opt/others
    git clone https://github.com/robertdavidgraham/masscan masscan_dic 
    make; make install
    mv bin/masscan /opt/others; rm -rf ../masscan_dic; cd ~
    ```

12. Replace following codebox with **~/.zshrc**

    ```sh
    export ZSH="$HOME/.oh-my-zsh"
    ZSH_THEME="robbyrussell"
    plugins=(git)
    source $ZSH/oh-my-zsh.sh

    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:/root/go/bin
    export PATH=$PATH:/opt/others

    ssh_users() {
        echo "[>] $(date)\n";
        ps aux | grep sshd | grep -vE "auto|listener|priv|root@pts" | rev | cut -d ' ' -f 1,6 | rev
    }

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

    bb_get_cert_brief() {
        if [[ $# -eq 1 ]]; then
            input="$1"
            echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text 2> /dev/null \
            | grep -E "(Issuer|Subject:|DNS:)" | grep -vE "(Issuers)" | sed "s/ //g"
        else
            while read -r input; do
                echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text 2> /dev/null \
                | grep -E "(Issuer|Subject:|DNS:)" | grep -vE "(Issuers)" | sed "s/ //g"
            done
        fi
    }

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

    bb_get_cert_subdomain_nuclei(){
        if [[ $# -eq 1 ]]; then
            input="$1"
            echo $input | nuclei -silent -t ~/nuclei-templates/ssl/ssl-dns-names.yaml -j | jq -r '.["extracted-results"][]' | sort -u
        else
            rm -rf .tmp
            while read -r input; do
                echo | openssl s_client -showcerts -servername "$input" -connect "$input" 2>/dev/null | openssl x509 -inform pem -noout -text 2> /dev/null \
                | grep "DNS:" | grep -v "Issuers" | sed "s/ //g" | sed "s/,/\n/g" | tr -d "DNS:" | sed "s/*.//g" >> .tmp
            done
            cat .tmp | sort -u; rm -rf .tmp
        fi
    }

    bb_email2domain_viewdns() {
        cf_clearance="<cookie>"
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

    bb_cidr_remove_cdn() {
        input=$(cat)
        if [[ -f "$input" ]]; then
            cat "$input" | mapcidr -silent | cdncheck -silent -e
        else
            echo "$input" | mapcidr -silent | cdncheck -silent -e
        fi
    }

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

    bb_ipscan_naabu(){
        ports="80,8000,8080,8880,2052,2082,2086,2095,443,2053,2083,2087,2096,8443,10443"
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

    bb_abuseipdb_subdomain(){
        abuseIPDB_cookie="cookie: <cookie>"
        abuseIPDB_user_agent="user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
        if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
        curl -s "https://www.abuseipdb.com/whois/$input" -H "$abuseIPDB_cookie" -H "$abuseIPDB_user_agent" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e "s/$/.$input/"
        unset abuseIPDB_cookie; unset abuseIPDB_user_agent
    }

    bb_chaos_search() {
        if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
        curl -s "https://chaos-data.projectdiscovery.io/index.json" | jq ".[].URL" --raw-output | grep $input
    }

    bb_chaos_download() {
        rm -rf chaos; mkdir -p chaos; cd chaos
        if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
        curl -s "https://chaos-data.projectdiscovery.io/index.json" | jq ".[].URL" --raw-output | grep $input > .tmp
        for link in $(cat .tmp); do wget -nv "$link"; done
        for file in $(ls); do unzip -qq $file 2> /dev/null; done; rm -rf *.zip; rm -rf .tmp; cd - 2> /dev/null
    }

    bb_github_subdomain(){
        export SRC_ENDPOINT=https://sourcegraph.com
        export SRC_ACCESS_TOKEN=<token>
        if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
        q=$(echo $input | sed -e 's/\./\\\./g')
        src search -json '([a-z\-]+)?:?(\/\/)?([a-zA-Z0-9]+[.])+('${q}') count:5000 fork=yes archive:yes' \
        | jq -r '.Results[] | .lineMatches[].preview, .file.path' | grep -oiE '([a-zA-Z0-9]+[.])+('${q}')' | awk '{print to lower($0)}' | sort -u
        unset SRC_ENDPOINT; unset SRC_ACCESS_TOKEN
    }

    bb_providers_subdomain() {
        if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
        echo $input | bb_crtsh_subdomain >> .tmp
        echo $input | bb_abuseipdb_subdomain >> .tmp
        echo $input | subfinder -all -silent >> .tmp
        cat .tmp | sort -u; rm -rf .tmp
    }

    bb_resfile_gen() {
        touch ~/.resolvers
        echo 8.8.4.4 > ~/.resolvers
        echo 129.250.35.251 >> ~/.resolvers
        echo 129.250.35.251 >> ~/.resolvers		
    }

    bb_wlgen_assetnote() {
        cd /opt/wordlists/
        wget -nv https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
        wget -nv https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt
        cat best-dns-wordlist.txt 2m-subdomains.txt | sort -u > static_assetnote_merged.txt
        rm -rf best-dns-wordlist.txt 2m-subdomains.txt; cd - > /dev/null
    }

    bb_wlgen_4char() {
        crunch 1 4 abcdefghijklmnopqrstuvwxyz1234567890 > /opt/wordlists/static_4_characters.txt
    }

    bb_wlgen_chaos() {
        cd /opt/wordlists 
        echo "-e *.*" | bb_chaos_download; rm -rf *.zip.1
        cat chaos/* | cut -d "." -f 1 | sort -u | grep -v -E "\*" | grep -v -E "\_" > static_chaos.txt; rm -rf /opt/wordlists/chaos; cd ~
    }

    bb_wlgen_dynamic() {
        cd /opt/wordlists/
        wget -nv https://raw.githubusercontent.com/AlephNullSK/dnsgen/master/dnsgen/words.txt
        wget -nv https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt
        cat words.txt words.txt.1 | sort -u > dynamic_dnsgalt.txt; rm words.txt words.txt.1; cd - > /dev/null
    }

    bb_dns_static() {
        if [[ "$1" == "-" ]]; then input=$(cat); else input="$1"; fi
        shuffledns -d "$input" -mode resolve -list "$2" -r ~/.resolvers -m massdns -o dns_static.txt
    }

    bb_dns_dynamic_dnsgen() {
        if [[ "$1" == "-" ]]; then input=$(cat); else input="$1"; fi
        dnsgen "$input" -w "$3" | shuffledns -d "$2" -mode resolve -r ~/.resolvers -m massdns -o dns_dynamic.txt
    }

    bb_dns_dynamic_altdns() {
        if [[ "$1" == "-" ]]; then input=$(cat); echo "$input" > temp_input.txt; altdns -i temp_input.txt -o temp_output.txt -w "$3"; else altdns -i "$1" -o temp_output.txt -w "$3"; fi
        shuffledns -d "$2" -mode resolve -r ~/.resolvers -m massdns -o dns_dynamic.txt < temp_output.txt
        rm -f temp_input.txt temp_output.txt
    }

    bb_livesubs_httpx() {
        if [[ $# -eq 1 ]]; then input="$1"; else input=$(cat); fi
        echo "$input" | httpx -silent -follow-host-redirects -title -status-code -cdn -tech-detect \
        -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15" -threads 1
        #-H "Referer: https://$input"
    }

    bb_vhost_fuzzing() {
        ffuf -w $2 -u "$1" -H "host: FUZZ" \ 
        -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac 0S X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15"
    }
    ```

13. Save the **~/.zshrc** and apply the changes

    ```sh
    source ~/.zshrc
    ```

