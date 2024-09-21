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
    ```

13. Save the **~/.zshrc** and apply the changes

    ```sh
    source ~/.zshrc
    ```
