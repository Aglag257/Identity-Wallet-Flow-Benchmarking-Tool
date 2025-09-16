
import express from "express";
import { v4 as uuid } from "uuid";
import { SignJWT, jwtVerify, importJWK, decodeProtectedHeader } from "jose";
import fetch from "node-fetch";
import { performance } from "node:perf_hooks";
import { createHash, webcrypto } from "node:crypto";

import fs from "node:fs";  

// globalThis.crypto = webcrypto;
const crypto = webcrypto;

const ITERATIONS   = Number(process.env.ITER ?? 50);          // #runs
const BIND = process.env.HOST ?? "127.0.0.1";
const LOCAL = "127.0.0.1";

const ISSUER_PORT   = Number(process.env.ISSUER_PORT   ?? 4000);
const VERIFIER_PORT = Number(process.env.VERIFIER_PORT ?? 5000);
const WALLET_PORT   = Number(process.env.WALLET_PORT   ?? 6000);

const ISSUER_BASE   = process.env.ISSUER_BASE_URL   ?? `http://${LOCAL}:${ISSUER_PORT}`;
const VERIFIER_BASE = process.env.VERIFIER_BASE_URL ?? `http://${LOCAL}:${VERIFIER_PORT}`;

const CREDENTIAL_TYPE = "UniversityDegreeCredential";

//  Results logging config
const IMPL_NAME   = process.env.IMPL_NAME ?? "json-bbs-revised";
const RESULTS_DIR  = process.env.RESULTS_DIR ?? "./results";
fs.mkdirSync(RESULTS_DIR, { recursive: true });

const RUN_ID       = new Date().toISOString().replace(/[:.]/g, "-");
const RESULTS_FILE = `${RESULTS_DIR}/benchmarks_${IMPL_NAME}_${RUN_ID}.jsonl`;

function writeRow(row) {
  fs.appendFileSync(RESULTS_FILE, JSON.stringify(row) + "\n", "utf8");
}

function last(a) {
  return a && a.length ? a[a.length - 1] : null;
}

/*  Experiment grid  */
const ATTR_COUNTS   = [5, 6, 7, 8, 9, 10];
const REVEAL_RATIOS = [0.20, 0.40, 0.60, 0.80, 1.00];

function resetStats() {
  runStats.issuer.t.length = 0;   runStats.issuer.cpu.length = 0;
  runStats.wallet.t.length = 0;   runStats.wallet.cpu.length = 0;
  runStats.verifier.t.length = 0; runStats.verifier.cpu.length = 0;
  runStats.payload.length = 0;    runStats.vcBytes.length = 0;
}

const preAuthCodes = Object.create(null);
const accessTokens  = Object.create(null);



const runStats = {
  issuer   : { t:[], cpu:[] },
  wallet   : { t:[], cpu:[] },
  verifier : { t:[], cpu:[] },
  payload  : [],
  vcBytes  : []             
};

function stats(arr){
  const n = arr.length, sorted = [...arr].sort((a,b)=>a-b);
  const mean = arr.reduce((s,x)=>s+x,0)/n;
  const std  = Math.sqrt(arr.reduce((s,x)=>s+(x-mean)**2,0)/n);
  const median = n&1 ? sorted[(n-1)>>1] : (sorted[n/2-1]+sorted[n/2])/2;
  return { mean, std, median, min:sorted[0], max:sorted[n-1] };
}

function digestDisclosure(disclosure){
  return createHash("sha256").update(disclosure).digest("base64url");
}

async function main(){
  /* key for ES256 */
  // Holder (wallet) key for ES256
  const holderKey = await crypto.subtle.generateKey(
    { name:"ECDSA", namedCurve:"P-256" }, true, ["sign","verify"]
  );
  const holderPubJwk = await crypto.subtle.exportKey("jwk", holderKey.publicKey);

  const signingKey = await crypto.subtle.generateKey(
    { name:"ECDSA", namedCurve:"P-256" }, true, ["sign","verify"]
  );

  /* ── ISSUER ─────────────────────────────────────────────── */
  const issuer = express()
        .use(express.json())
        .use(express.urlencoded({ extended:false }));      

  issuer.get("/credential-offer", (_req,res)=>{
    const subject=`did:example:${uuid()}`, code=uuid();
    const pin = String(Math.floor(100000 + Math.random()*900000)); 
    preAuthCodes[code] = { subject, pin };
    res.json({
      credential_issuer: ISSUER_BASE,
      grants:{ "urn:ietf:params:oauth:grant-type:pre-authorized_code":
               { "pre-authorized_code":code, user_pin_required:true } },
      tx_code: pin                                       
    });
  });

  issuer.post("/token",(req,res)=>{
    if(req.body.grant_type!=="urn:ietf:params:oauth:grant-type:pre-authorized_code")
      return res.status(400).json({error:"unsupported_grant_type"});
    const rec = preAuthCodes[req.body["pre-authorized_code"]];
    if(!rec) return res.status(400).json({error:"invalid_grant"});
    if(rec.pin && req.body.tx_code!==rec.pin)
      return res.status(400).json({error:"invalid_tx_code"});

    const token=uuid(); accessTokens[token]=rec.subject;

    const c_nonce = crypto.randomUUID().replace(/-/g,"");
    accessTokens[token+":nonce"] = c_nonce;

    res.json({access_token:token,token_type:"Bearer",expires_in:600,
              c_nonce, c_nonce_expires_in:600});
  });

  issuer.post("/credential",async(req,res)=>{
    const t0=performance.now(), cpu0=process.cpuUsage();
    const token=(req.headers.authorization||"").split(" ")[1];
    if(!token||!accessTokens[token]) return res.status(401).json({error:"invalid_token"});
    const subject=accessTokens[token];

    const cnonce = accessTokens[token + ":nonce"];

    const proofJwt = req.body?.proofs?.jwt?.[0];
    if(!proofJwt) return res.status(400).json({error:"invalid_proof", error_description:"missing proofs.jwt"});
    let holderJwk, proof;
    try{
      const hdr = decodeProtectedHeader(proofJwt);
      if(!hdr?.jwk) throw new Error("missing holder jwk in proof header");
      holderJwk = hdr.jwk;
      const holderPub = await importJWK(holderJwk, "ES256");
      const { payload } = await jwtVerify(proofJwt, holderPub);
      proof = payload;
    }catch(e){
      return res.status(400).json({error:"invalid_proof", error_description:e.message});
    }
    if(proof.aud !== ISSUER_BASE) {
      return res.status(400).json({error:"invalid_proof", error_description:"aud mismatch"});
    }
    if(proof.nonce !== cnonce){
      return res.status(400).json({error:"invalid_nonce"});
    }

    const count = Math.max(1, Math.min(200, Number(req.body?.attr_count ?? 5)));

    const disclosures = Array.from({ length: count }, (_, i) =>
      Buffer.from(JSON.stringify([
        crypto.randomUUID(),         
        `attr_${i+1}`,               
        `value_${i+1}`               
      ])).toString("base64url")
    );

    const _sd = disclosures.map(digestDisclosure);

    const jwt = await new SignJWT({
      iss: ISSUER_BASE,
      sub:subject,
      iat:Math.floor(Date.now()/1000),
      exp:Math.floor(Date.now()/1000+3600),
      vct:`urn:example:${CREDENTIAL_TYPE}`,  
      cnf:{ jwk: holderJwk },
      _sd
    }).setProtectedHeader({alg:"ES256",typ:"dc+sd-jwt"}) 
      .sign(signingKey.privateKey);

    runStats.issuer.t.push(performance.now()-t0);
    const cpu = process.cpuUsage(cpu0);
    runStats.issuer.cpu.push((cpu.user + cpu.system) / 1000);


    const cred={format:"dc+sd-jwt",credential:jwt,disclosures};
    res.json(cred);
  });

  issuer.listen(ISSUER_PORT, BIND,()=>console.log(`[issuer]  → bind http://${BIND}:${ISSUER_PORT} (internal ${ISSUER_BASE})`));

  /* ── VERIFIER ───────────────────────────────────────────── */
  const verifier = express().use(express.json());
  verifier.post("/verify",async(req,res)=>{
    const t0=performance.now(), cpu0=process.cpuUsage();
    try{

      const { credential, disclosures, kb_jwt } = req.body;
      // 1) Verify Issuer-signed SD-JWT
      const { payload: vc, protectedHeader } =
        await jwtVerify(credential, signingKey.publicKey);
      // 2) Check disclosures against vc._sd digests
      if (!Array.isArray(vc._sd)) throw new Error("sd_missing");

      const sdArray = vc._sd;
      if (new Set(sdArray).size !== sdArray.length) {
        throw new Error("sd_duplicates");
      }

      const sdSet = new Set(sdArray);

      for (const d of disclosures) {
        const h = digestDisclosure(d);
        if (!sdSet.has(h)) throw new Error("digest_mismatch");
        sdSet.delete(h);
      }

      // 3) Verify KB-JWT (holder binding)
      const kbHdr = decodeProtectedHeader(kb_jwt);
      if(kbHdr?.typ !== "kb+jwt") throw new Error("kb_typ");
      if(!vc?.cnf?.jwk) throw new Error("missing_cnf");
      const holderPub = await importJWK(vc.cnf.jwk, "ES256");
      const { payload: kb } = await jwtVerify(kb_jwt, holderPub);

      // 4) Validate audience, nonce, and sd_hash
      if(kb.aud !== VERIFIER_BASE) throw new Error("kb_aud");
      if(!verifierNonces[kb.nonce]) throw new Error("kb_nonce");
      delete verifierNonces[kb.nonce];

      const sdForHash = credential + "~" + disclosures.join("~") + "~";
      const expected = createHash("sha256").update(sdForHash).digest("base64url");
      if(kb.sd_hash !== expected) throw new Error("kb_sd_hash");

      runStats.verifier.t.push(performance.now()-t0);

      const cpu = process.cpuUsage(cpu0);
      runStats.verifier.cpu.push((cpu.user + cpu.system) / 1000);

      res.json({verified:true});
    }catch(e){ res.status(400).json({verified:false,error:e.message}); }
  });

  const verifierNonces = Object.create(null);
  verifier.get("/nonce", (_req,res)=>{
    const n = crypto.randomUUID().replace(/-/g,"");
    verifierNonces[n] = true;
    res.json({nonce:n});
  });

  verifier.listen(VERIFIER_PORT,BIND,()=>console.log(`[verifier] → bind http://${BIND}:${VERIFIER_PORT} (internal ${VERIFIER_BASE})`));

  /* ── WALLET (driver) ───────────────────────────────────── */
  const wallet = express().use(express.json());
  wallet.post("/run",async(_req,res)=>{
    const t0=performance.now(), cpu0=process.cpuUsage();
    const attrCount  = Math.max(1, Number(_req.body?.attrCount ?? 5));
    const revealRatio = Math.min(1, Math.max(0, Number(_req.body?.revealRatio ?? 0.2)));


    const offer = await fetch(`${ISSUER_BASE}/credential-offer`).then(r=>r.json());
    const code  = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"];

    const params = new URLSearchParams({                    
      grant_type:"urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code":code,
      tx_code: offer.tx_code                              
    });
    const {access_token,c_nonce}=await fetch(`${offer.credential_issuer}/token`,{
      method:"POST",headers:{ "content-type":"application/x-www-form-urlencoded" },
      body:params
    }).then(r=>r.json());


     const issuanceProof = await new SignJWT({
       aud: offer.credential_issuer,
       nonce: c_nonce,
       iat: Math.floor(Date.now()/1000),
       exp: Math.floor(Date.now()/1000 + 300)
     }).setProtectedHeader({
       alg:"ES256",
       typ:"openid4vci-proof+jwt",
       jwk: holderPubJwk
     }).sign(holderKey.privateKey);
    
     const vc = await fetch(`${offer.credential_issuer}/credential`,{
       method:"POST",
       headers:{ "content-type":"application/json", Authorization:`Bearer ${access_token}` },
       body:JSON.stringify({
         format:"dc+sd-jwt",                
         proofs:{ jwt:[issuanceProof] },
         attr_count: attrCount                 
       })
     }).then(r=>r.json());

    const total = Array.isArray(vc.disclosures) ? vc.disclosures.length : 0;
    const k = Math.max(0, Math.min(total, Math.floor(revealRatio * total)));

    const selectedDisclosures = vc.disclosures.slice(0, k);



    runStats.vcBytes.push(Buffer.byteLength(JSON.stringify(vc)));

    const { nonce } = await fetch(`${VERIFIER_BASE}/nonce`).then(r=>r.json());;

    // Build SD-JWT+KB
    const sdForHash = vc.credential + "~" + selectedDisclosures.join("~") + "~";
    const sd_hash = createHash("sha256").update(sdForHash).digest("base64url");

    const kbJwt = await new SignJWT({
      nonce,
      aud: VERIFIER_BASE,
      iat: Math.floor(Date.now()/1000),
      sd_hash
    }).setProtectedHeader({ alg:"ES256", typ:"kb+jwt" })
      .sign(holderKey.privateKey);

    const payloadSize = Buffer.byteLength(kbJwt) +
      Buffer.byteLength(vc.credential) + Buffer.byteLength(selectedDisclosures.join(""));
    runStats.payload.push(payloadSize);
    const verification = await fetch(`${VERIFIER_BASE}/verify`,{
      method:"POST",headers:{ "content-type":"application/json" },
      body:JSON.stringify({ credential: vc.credential, disclosures: selectedDisclosures, kb_jwt: kbJwt })
    }).then(r=>r.json());

    runStats.wallet.t.push(performance.now()-t0);
    const cpu = process.cpuUsage(cpu0);

    runStats.wallet.cpu.push((cpu.user + cpu.system) / 1000); // ms
    





    writeRow({
      type: "run",
      impl: IMPL_NAME,
      attrCount,
      revealRatio,
      metrics: {
        issuer_ms:   last(runStats.issuer.t),
        wallet_ms:   last(runStats.wallet.t),
        verifier_ms: last(runStats.verifier.t),

        issuer_cpu_ms:   last(runStats.issuer.cpu),
        wallet_cpu_ms:   last(runStats.wallet.cpu),
        verifier_cpu_ms: last(runStats.verifier.cpu),

        payload_present_bytes: payloadSize,
        vc_size_bytes: last(runStats.vcBytes)
      }
    });
    res.json({verification});



  });
  wallet.listen(WALLET_PORT,BIND,()=>{
    console.log(`[wallet]  → bind http://${BIND}:${WALLET_PORT} (driver on http://${LOCAL}:${WALLET_PORT})`);
    runBenchmark().catch(e=>{console.error(e);process.exit(1);});
  });
}

/* ─── Benchmark loop ─────────────────────────────────────────────── */
async function runBenchmark(){
  const summary = [];

  for (const A of ATTR_COUNTS) {
    for (const R of REVEAL_RATIOS) {
      resetStats();
      console.log(`\n--- Running ${ITERATIONS} runs for attrCount=${A}, reveal=${Math.round(R*100)}% ---`);

      for (let i = 0; i < ITERATIONS; i++) {
        const r = await fetch(`http://127.0.0.1:${WALLET_PORT}/run`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ attrCount: A, revealRatio: R })
        }).then(r => r.json());

        if (!r.verification?.verified) {
          throw new Error(`Run #${i+1} failed verification (A=${A}, R=${R})`);
        }
        if ((i+1) % 10 === 0) {
          console.log(`✓ completed ${i+1}/${ITERATIONS}`);
        }
      }

      
      const res = {
        "Issuer time (ms)"  : stats(runStats.issuer.t),
        "Wallet time (ms)"  : stats(runStats.wallet.t),
        "Verifier time (ms)": stats(runStats.verifier.t),
        "Issuer CPU (ms)"   : stats(runStats.issuer.cpu),
        "Wallet CPU (ms)"   : stats(runStats.wallet.cpu),
        "Verifier CPU (ms)" : stats(runStats.verifier.cpu),
        "Payload bytes"     : stats(runStats.payload),
        "VC bytes"          : stats(runStats.vcBytes)
      };

      const table = {};
      for (const [k, v] of Object.entries(res)) {
        table[k] = {
          mean:   v.mean.toFixed(2),
          std:    v.std.toFixed(2),
          median: v.median.toFixed(2),
          min:    v.min.toFixed(2),
          max:    v.max.toFixed(2)
        };
      }

      console.log(`\n======== Results for attrCount=${A}, reveal=${Math.round(R*100)}% ========\n`);
      console.table(table);

      writeRow({
        type: "summary",
        impl: IMPL_NAME,
        attrCount: A,
        revealRatio: R,
        metrics: {
          issuer_ms:            res["Issuer time (ms)"].mean,
          wallet_ms:            res["Wallet time (ms)"].mean,
          verifier_ms:          res["Verifier time (ms)"].mean,
          issuer_cpu_ms:        res["Issuer CPU (ms)"].mean,
          wallet_cpu_ms:        res["Wallet CPU (ms)"].mean,
          verifier_cpu_ms:      res["Verifier CPU (ms)"].mean,
          payload_present_bytes:res["Payload bytes"].mean,
          vc_size_bytes:        res["VC bytes"].mean
        }
      });
      summary.push({
        attrCount: A,
        revealPct: Math.round(R*100),
        wallet_ms_mean: table["Wallet time (ms)"].mean,
        payload_bytes_mean: table["Payload bytes"].mean,
        vc_bytes_mean: table["VC bytes"].mean
      });
    }
  }

  if (summary.length) {
    console.log("\n=========== Compact summary (means only) ===========");
    console.table(summary);
  }

  console.log("\nComplexity (unchanged): O(d) where d = #disclosed attributes.");
  process.exit(0);
}


main().catch(e=>{console.error(e);process.exit(1);});
