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

# BBS 2023 + unlinkable VP (mattr pairing cryto library)
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

# P.S. If you want comparable results between bbs+ and 2023 bbs revisioned you should run the bbs+ flow like this so it doesnt use the native libraries (that dont exist in the bbs2023 implementation) making it more efficient
node --experimental-permission --allow-fs-read=* --allow-fs-write=* --allow-worker --allow-wasi jsonBbsPlus.mjs

```

## For plots 
```bash

pip install pandas numpy matplotlib
python3 plot.py --dir ./<results folder> --out <plots folder>
python3 plot.py --dir ./results_official --out paper_plots
python plot.py --dir ./multi_device_results --out multi_device_plots_new
python plot.py --dir ./mobile_comparison --out mobile_comparison
```

## Quick start (Android / Termux)


1. Install **F-Droid**, then **Termux** from F-Droid.
2. In Termux:

```bash
pkg update -y && pkg upgrade -y
pkg install -y git nodejs-lts openssl-tool
pkg install -y clang make python pkg-config
git clone <repo url>
cd Identity-Wallet-Flow-Benchmarking-Tool
npm install
export RESULTS_DIR=./results
export IMPL_NAME="bbs2023-pairing-crypto"
node bbsRevisedRust.mjs
export IMPL_NAME="json-bbs-plus"
node jsonBbsPlus.mjs
export IMPL_NAME="jwt-legacy"
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

