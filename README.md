# Custom BBB (Bug Bounty Bash) Functions
This repository contains a collection of custom Bash functions designed to streamline and enhance the bug bounty hunting process. Each function serves a specific purpose, from gathering SSL certificate details to scanning for open ports and extracting subdomain information. By leveraging these functions, bug hunters can automate repetitive tasks, efficiently collect data, and focus more on analysis and exploitation. Explore the functions, adapt them to your workflow, and contribute to the ongoing improvement of this toolkit for the bug bounty community!


## Setup Guide
To effectively utilize the functions provided in this repository, it is crucial to set up your local environment correctly. For this purpose, I highly recommend using an Ubuntu Server 22.04 VPS. This version of Ubuntu is known for its stability, security, and extensive support, making it an ideal choice for running the scripts and tools included in this repository.

```bash
# install requirement tools
git clone https://github.com/hunThubSpace/ReconVPS.git; cd ReconVPS; bash reconVPS.sh

# append content of following file into ~/.zshrc file
git clone https://github.com/hunThubSpace/BB-BugBountyBash.git; cd BB-BugBountyBash; cat zshfile.txt >> ~/.zshrc; source ~/.zshrc

# optional: you can use following command to generate wordlists for dns bruteforces
bb_wlgen_4char; bb_wlgen_alljhaddix; bb_wlgen_assetnote; bb_wlgen_nokovo; bb_wlgen_chaos

# optional: you can add following command to add valid dns servers as resolvers
bb_resfile_gen
```
