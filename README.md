# Identity Wallet Flow Benchmarking Tool


This is a benchmarking tool, as a result many implementation details were though of as out of scope, so there are some deviations from the original protocols that were not computationally different between the flows, so no difference in our case


To run in an android:

1) Install F-Droid
2) install Termux from there 

Then in Termux:
3) pkg update -y && pkg upgrade -y
4) pkg install -y nodejs-lts git
5) node -v    (should be ≥ 18)
6) mkdir -p ~/conf-metrics && cd ~/conf-metrics
7) npm init -y
8) npm i express uuid jose node-fetch
9) jq '.type="module"' package.json > package.tmp && mv package.tmp package.json #(creates the package.json)
10) nano <name of file>.mjs
11) copy paste the code inside that file, save and exit
12) termux-wake-lock  #Optional: keep the CPU awake while it runs
13) node <name of file>.mjs

P.S. The only thing needed to remove from the code files in the repo is this command:

"globalThis.crypto = webcrypto;" and keep the rest as is

