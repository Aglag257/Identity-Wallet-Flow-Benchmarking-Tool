# Identity Wallet Flow Benchmarking Tool

(THIS IS NOT FULLY READY YET - SOME PARTS (IN THE DOCKERIZATION MIGHT NOT FULLY WORK ATM))


This is a benchmarking tool, that compares different crypto operations for different implementations of common digital-identity credential flows. This is not a production wallet/issuer/verifier. As a result, we intentionally relax or omit several protocol features that either don’t change computational cost, or they create bloat and noise for the benchmarking purpose of this tool, which is to compare the cryptographic operations (details below).


## Contents:
jwt_legacy.mjs – SD-JWT VC issuance (pre-authorized code) + KB-JWT holder binding; verification with SD hashing.

jsonBbsRevised.mjs – BBS 2023 credentials + unlinkable, selective-disclosure presentations (derived proofs).

jsonBbsPlus.mjs – BBS+ flow variant.

All three scripts launch Issuer, Verifier, Wallet servers in one Node process and then run the benchmark driver.

## Quick start (Docker):

```bash
# BBS 2023 + unlinkable VP
docker compose --profile revised up --build

# BBS+ variant
docker compose --profile plus up --build

# SD-JWT VC + KB-JWT
docker compose --profile legacy up --build

docker compose --profile pairing up --build

```

## Quick start (Linux, no Docker)

```bash
# 1) System deps
sudo apt-get update
sudo apt-get install -y curl git python3 make g++ ca-certificates

# 2) Node.js ≥ 18
node -v
npm -v

# 3) Clone & install
git clone <this-repo-url> wallet-bench
cd wallet-bench
npm ci   

# 4) Run any flow (examples)
  node jwt_legacy.mjs
  node jsonBbsRevised.mjs
```

## Quick start (Android / Termux)


1. Install **F-Droid**, then **Termux** from F-Droid.
2. In Termux:

```bash
pkg update -y && pkg upgrade -y
pkg install -y nodejs-lts git jq
node -v   # should be ≥ 18
mkdir -p ~/conf-metrics && cd ~/conf-metrics
git clone <this-repo-url> .
jq '.type="module"' package.json > package.tmp && mv package.tmp package.json
npm ci
# Choose and run one script:
node jwt_legacy.mjs
```

## What the benchmark does

* Launches **Issuer**, **Verifier**, **Wallet (driver)** in one process.
* Iterates a grid:

  * **Attribute counts:** `[5, 6, 7, 8, 9, 10]`
  * **Reveal ratios:** `[0.20, 0.40, 0.60, 0.80, 1.00]`
* For each grid point runs `ITER` trials, recording:

  * **Wall time (ms)** and **CPU time (ms)** for Issuer, Wallet, Verifier
  * **Payload bytes** (presentation to Verifier) and **VC bytes** (issuance response)
* Prints per-grid statistics (mean, std, median, min, max) and a compact summary.



## Scope

Things we omitted:

* **Discovery & metadata** (e.g., OpenID Federation, full OID4VCI/OID4VP metadata, `.well-known` endpoints) — **omitted**. The benchmark hard-codes endpoints because metadata/federation adds network round-trips and parsing but does not alter signing/proof costs in our testbed.
  
* **Trust establishment** — **relaxed.** In some flows the Verifier trusts a key provided by the Wallet/response (no full chain/DID resolution). Real systems must validate Issuer keys via DID methods/registries or trust frameworks; we skip that to avoid anchoring to a specific DID resolver and to keep crypto operations comparable across flows. ([W3C][2])
* **Statefulness & persistence** — all state is **ephemeral in-memory**; no DB; restart resets everything.

These choices keep the comparison focused on:

* Token exchanges and proofs mandated by each format/profile,
* The **selective disclosure** mechanics (disclosure lists vs BBS derived proofs),
* Holder binding (e.g., **KB-JWT** PoP for SD-JWT VC).

for plots 

pip install pandas numpy matplotlib
python3 plot.py --dir ./results_official --out paper_plots2
