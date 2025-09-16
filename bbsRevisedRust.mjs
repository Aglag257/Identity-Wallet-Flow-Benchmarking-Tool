import express from "express";
import { v4 as uuid } from "uuid";
import { performance } from "node:perf_hooks";
import { SignJWT, jwtVerify, generateKeyPair as joseGenKP, exportJWK, importJWK } from "jose";
import crypto from "node:crypto";
import * as pairingCrypto from '@mattrglobal/pairing-crypto';

import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import fs from "node:fs";

/*  Tunables */
const BIND  = process.env.HOST ?? "127.0.0.1";
const LOCAL = "127.0.0.1";
const ISSUER_PORT   = Number(process.env.ISSUER_PORT   ?? 4000);
const VERIFIER_PORT = Number(process.env.VERIFIER_PORT ?? 5000);
const WALLET_PORT   = Number(process.env.WALLET_PORT   ?? 7000);
const ITER          = Number(process.env.ITER          ?? 50);
const url = (port, path) => `http://${LOCAL}:${port}${path}`;

/*  Experiment grid  */
const ATTR_COUNTS   = [5, 6, 7, 8, 9, 10];    
const REVEAL_RATIOS = [0.20, 0.40, 0.60, 0.80, 1.00];

const IMPL_NAME   = process.env.IMPL_NAME ?? "bbs2023-pairing-crypto";
const RESULTS_DIR  = process.env.RESULTS_DIR ?? "./results";
fs.mkdirSync(RESULTS_DIR, { recursive: true });

const RUN_ID       = new Date().toISOString().replace(/[:.]/g, "-");
const RESULTS_FILE = `${RESULTS_DIR}/benchmarks_${IMPL_NAME}_${RUN_ID}.jsonl`;

function writeRow(row) {
  fs.appendFileSync(RESULTS_FILE, JSON.stringify(row) + "\n", "utf8");
}
const last = (a) => (a && a.length ? a[a.length - 1] : null);

function resetStats() {
  M.issuer.t.length = 0;   M.issuer.cpu.length = 0;
  M.wallet.t.length = 0;   M.wallet.cpu.length = 0;
  M.verifier.t.length = 0; M.verifier.cpu.length = 0;
  M.payload.length = 0;    M.vcBytes.length = 0;
}


/*  Helpers  */
const TXT = new TextEncoder();
const toBytes = (s) => TXT.encode(String(s));
const b64 = (u8) => Buffer.from(u8).toString("base64");
const b64url = (u8) => Buffer.from(u8).toString("base64url");
const fromB64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
function fromB64url(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; return Uint8Array.from(Buffer.from(s,'base64')); }
const stats=(arr)=>{const n=arr.length,s=[...arr].sort((a,b)=>a-b); const mean=arr.reduce((a,x)=>a+x,0)/n;
  const std=Math.sqrt(arr.reduce((a,x)=>a+(x-mean)**2,0)/n); const med=n&1?s[(n-1)>>1]:(s[n/2-1]+s[n/2])/2; return {mean,std,median:med,min:s[0],max:s[n-1]};};
async function getJSON(u, init){
  const r = await fetch(u, init);
  const ct = r.headers.get("content-type") || "";
  const text = await r.text();
  if (!r.ok || !ct.includes("application/json")) {
    throw new Error(`Expected JSON from ${u} → ${r.status} ${r.statusText} (${ct})\n` + text.slice(0,200));
  }
  return JSON.parse(text);
}

/*  Metric store  */
const M = {
  issuer: { t:[], cpu:[] },
  wallet: { t:[], cpu:[] },
  verifier: { t:[], cpu:[] },
  payload: [],
  vcBytes: []
};

/*  Global issuer key  */
const issuerBbs = await pairingCrypto.bbs.bls12381_sha256.generateKeyPair({ ciphersuite: 'BLS12-381-SHA-256' });

/* 
 * 1) ISSUER — OID4VCI pre-authorized code + nonce + ldp_vc
 *  */
async function startIssuer(port=ISSUER_PORT){
  const app = express().use(express.json()).use(express.urlencoded({extended:false}));

  // Ephemeral stores
  const preAuth = Object.create(null);   
  const tokens  = Object.create(null); 
  const nonces  = Object.create(null);    

  app.get("/credential-offer", (_req,res)=>{
    const did = `did:example:${uuid()}`;
    const code = uuid();
    preAuth[code] = { sub: did };

    res.json({
      credential_issuer: `http://${LOCAL}:${port}`,
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": code, "tx_code": {}
        }
      },
      credentials: [{
        format: "ldp_vc",
        types: ["VerifiableCredential","UniversityDegreeCredential"],
        cryptosuite: "bbs-2023"
      }]
    });
  });

  app.post("/token",(req,res)=>{
    if(req.body.grant_type !== "urn:ietf:params:oauth:grant-type:pre-authorized_code")
      return res.status(400).json({error:"unsupported_grant_type"});
    const rec = preAuth[req.body["pre-authorized_code"]];
    if(!rec) return res.status(400).json({error:"invalid_grant"});
    const at = uuid();
    tokens[at] = rec.sub;
    res.json({ access_token: at, token_type:"Bearer", expires_in: 600 });
  });

  app.post("/nonce",(_req,res)=>{
    const n = crypto.randomUUID().replace(/-/g,"");
    nonces[n] = true;
    res.set("Cache-Control","no-store").json({ c_nonce: n });
  });

  app.post("/credential", async (req,res)=>{
    const t0 = performance.now(), cpu0 = process.cpuUsage();
    try{
      const at = req.headers.authorization?.split(" ")[1];
      if(!at || !tokens[at]) return res.status(401).json({error:"invalid_token"});
      const subject = tokens[at];

      const attrCount = Math.max(4, Math.min(200, Number(req.body?.attr_count ?? 5)));

      const baseAttrs = [
        ["givenName",  "Alice"],
        ["familyName", "Anderson"],
        ["degree",     "Computer Science"],
        ["gpa",        "4.0"]
      ];

      const attrs = [];
      for (let i = 0; i < Math.min(attrCount, baseAttrs.length); i++) {
        attrs.push(baseAttrs[i]);
      }
      for (let i = baseAttrs.length + 1; i <= attrCount; i++) {
        attrs.push([`attr_${i}`, `value_${i}`]);
      }


      const jws = req.body?.proofs?.jwt?.[0];
      if(!jws) return res.status(400).json({error:"missing_proofs"});
      const { payload, protectedHeader } = await jwtVerify(
        jws,
        async (h)=> {                        
          if (h.jwk) return await importJWK(h.jwk, h.alg);
          throw new Error("no key material"); 
        }
      );
      if (protectedHeader.typ !== "openid4vci-proof+jwt") throw new Error("typ");
      if (!nonces[payload.nonce]) throw new Error("nonce");
      delete nonces[payload.nonce];

      const now = new Date().toISOString();
      const seed = uuid();

      const credSub = { id: subject, seed };
      for (const [k, v] of attrs) credSub[k] = v;

      const vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential","UniversityDegreeCredential"],
        issuer: `http://${LOCAL}:${ISSUER_PORT}`,
        issuanceDate: now,
        credentialSubject: credSub,
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "bbs-2023",
          created: now,
          proofPurpose: "assertionMethod",
          verificationMethod: "did:example:issuer#bbs"
        }
      };

      const messages = [
        vc.issuer,
        vc.credentialSubject.seed,
        ...attrs.map(([_, v]) => v)
      ].map(toBytes);

      const signature = await pairingCrypto.bbs.bls12381_sha256.sign({
        secretKey: issuerBbs.secretKey,
        publicKey: issuerBbs.publicKey,
        header: new Uint8Array(),
        messages,
        ciphersuite: "BLS12-381-SHA-256"
      });

      const base = { signature: b64(signature), publicKey: b64(issuerBbs.publicKey), messages: messages.length };

      const { user, system } = process.cpuUsage(cpu0);
      M.issuer.t.push(performance.now()-t0);
      M.issuer.cpu.push((user+system) / 1000);

      const respPayload = { credential: vc, base_proof: base };
      M.vcBytes.push(Buffer.byteLength(JSON.stringify(respPayload)));
      res.json(respPayload);
    }catch(e){
      console.error("[issuer:/credential] %s", e?.stack || e);
      res.status(400).json({error:String(e?.message||e)});
    }
  });

  app.use((req,res)=>res.status(404).json({error:"not_found", path:req.url, method:req.method}));

  return new Promise((ok)=>app.listen(port,BIND,()=>{
    console.log(`[issuer]   → http://${BIND}:${port} (internal http://${LOCAL}:${ISSUER_PORT})`);
    ok();
  }));
}

/* 
 * 2) VERIFIER — unlinkable selective disclosure with BBS derived proofs
 *  */
async function startVerifier(port=VERIFIER_PORT){
  const app = express().use(express.json());
  const nonces = Object.create(null);

  app.get("/nonce",(_q,r)=>{
    const n = b64url(crypto.randomBytes(16));
    nonces[n] = true;
    r.json({ nonce:n });
  });

  app.post("/verify", async (req,res)=>{
    const t0 = performance.now(), cpu0 = process.cpuUsage();
    try{
      const { vp_token } = req.body;
      if(!vp_token?.nonce || !nonces[vp_token.nonce])
        return res.status(400).json({verified:false, reason:"nonce"});
      delete nonces[vp_token.nonce];

      const revealed = vp_token.revealed; // [{idx,val}]
      const msgs = revealed.map(r=>toBytes(r.val));

      const ok = await pairingCrypto.bbs.bls12381_sha256.verifyProof({
        proof: fromB64(vp_token.proof),
        publicKey: fromB64(vp_token.issuerPublicKey),
        header: new Uint8Array(),
        presentationHeader: fromB64url(vp_token.nonce),
        disclosedMessages: msgs,
        disclosedMessageIndexes: revealed.map(r=>r.idx),
        ciphersuite: "BLS12-381-SHA-256"
      });

      const { user, system } = process.cpuUsage(cpu0);
      M.verifier.t.push(performance.now()-t0);
      M.verifier.cpu.push((user+system) / 1000);

      res.json({ verified: !!ok });
    }catch(e){
      res.status(400).json({ verified:false, error:String(e?.message||e) });
    }
  });

  app.use((req,res)=>res.status(404).json({error:"not_found", path:req.url, method:req.method}));

  return new Promise((ok)=>app.listen(port,BIND,()=>{
    console.log(`[verifier] → http://${BIND}:${port} (internal http://${LOCAL}:${VERIFIER_PORT})`);
    ok();
  }));
}

/* 
 * 3) WALLET — pre-authorized issuance + unlinkable presentation
 */
async function startWallet(port=WALLET_PORT){
  const app = express().use(express.json());

  app.post("/run", async (_q,res)=>{
    const t0 = performance.now(), cpu0 = process.cpuUsage();
    try {
      // parameters for this run (injected by runBenchmark)
      const attrCount   = Math.max(4, Number(_q.body?.attrCount ?? 5));     // min 4 to keep canonical
      const revealRatio = Math.min(1, Math.max(0, Number(_q.body?.revealRatio ?? 0.2)));

      // 1) Offer
      const offer = await getJSON(url(ISSUER_PORT, "/credential-offer"));
      const code = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"];

      // 2) Token
      const { access_token } = await getJSON(url(ISSUER_PORT, "/token"),{
        method:"POST", headers:{ "content-type":"application/json" },
        body:JSON.stringify({ grant_type:"urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code":code })
      });

      // 3) Issuer Nonce (c_nonce)
      const { c_nonce } = await getJSON(url(ISSUER_PORT, "/nonce"),{method:"POST"});

      // 4) Minimal attestation proof (JWT) — includes c_nonce
      const { publicKey: holderPub, privateKey: holderPriv } = await joseGenKP("ES256");
      const holderPubJwk = await exportJWK(holderPub);
      const attJws = await new SignJWT({
        aud: offer.credential_issuer,
        nonce: c_nonce
      }).setProtectedHeader({
        alg: "ES256",
        typ: "openid4vci-proof+jwt",
        jwk: holderPubJwk
      }).sign(holderPriv);

      // 5) Credential request
      const credRes = await getJSON(url(ISSUER_PORT, "/credential"),{
        method:"POST",
        headers:{ "content-type":"application/json", Authorization:`Bearer ${access_token}` },
        body:JSON.stringify({
          format:"ldp_vc",
          proofs:{ jwt: [attJws]  },
          c_nonce,
          attr_count: attrCount     
        })
      });

      // 6) Build unlinkable VP with BBS derived proof (dynamic attrs + reveal %)
      const vc = credRes.credential;
      const base = credRes.base_proof;
      const issuerPublicKey = fromB64(base.publicKey);
      const signature = fromB64(base.signature);

      const orderedPairs = [];
      const cs = vc.credentialSubject;
      const canonical = ["givenName","familyName","degree","gpa"];
      for (const k of canonical) if (k in cs) orderedPairs.push([k, cs[k]]);
      let i = 5;
      while (true) {
        const k = `attr_${i}`;
        if (!(k in cs)) break;
        orderedPairs.push([k, cs[k]]);
        i++;
      }

      const msgs = [
        vc.issuer,
        cs.seed,
        ...orderedPairs.map(([_, v]) => v)
      ].map(toBytes);

      if ((base?.messages | 0) !== msgs.length) {
        throw new Error(`message count mismatch: signed ${base?.messages}, have ${msgs.length}`);
      }

      const totalAttrs = orderedPairs.length;
      const k = Math.max(0, Math.min(totalAttrs, Math.floor(revealRatio * totalAttrs)));

      const reveal = Array.from({ length: k }, (_, j) => 2 + j);

      const { nonce } = await getJSON(url(VERIFIER_PORT, "/nonce"));

      const revealMsgArray = pairingCrypto.utilities.convertToRevealMessageArray(msgs, reveal);
      const proof = await pairingCrypto.bbs.bls12381_sha256.deriveProof({
        publicKey: issuerPublicKey,
        signature,
        header: new Uint8Array(),
        messages: revealMsgArray,
        presentationHeader: fromB64url(nonce),
        disclosedMessageIndexes: reveal,
        ciphersuite: "BLS12-381-SHA-256"
      });

      const vp_token = {
        nonce,
        issuerPublicKey: base.publicKey,
        revealed: reveal.map(i=>({ idx:i, val: Buffer.from(msgs[i]).toString() })),
        proof: b64(proof)
      };

      const body = JSON.stringify({ vp_token });
      M.payload.push(Buffer.byteLength(body));

      const ok = await getJSON(url(VERIFIER_PORT, "/verify"),{
        method:"POST", headers:{ "content-type":"application/json" }, body
      });

      const { user, system } = process.cpuUsage(cpu0);
      M.wallet.t.push(performance.now()-t0);
      M.wallet.cpu.push((user+system) / 1000);

      writeRow({
        type: "run",
        impl: IMPL_NAME,
        attrCount,
        revealRatio,
        metrics: {
          issuer_ms:   last(M.issuer.t),
          wallet_ms:   last(M.wallet.t),
          verifier_ms: last(M.verifier.t),

          issuer_cpu_ms:   last(M.issuer.cpu),
          wallet_cpu_ms:   last(M.wallet.cpu),
          verifier_cpu_ms: last(M.verifier.cpu),
          payload_present_bytes: last(M.payload),
          vc_size_bytes:         last(M.vcBytes)
        }
      });
      res.json({ verified: ok.verified, vcBytes: JSON.stringify(credRes).length });
    } catch (e) {
      console.error("[wallet:/run]", e?.stack || e);
      res.status(500).json({ verified:false, error:String(e?.message||e) });
    }
  });

  // JSON 404 LAST
  app.use((req,res)=>res.status(404).json({error:"not_found", path:req.url, method:req.method}));

  return new Promise((ok)=>app.listen(port,BIND,()=>{
    console.log(`[wallet]   → http://${BIND}:${port} (internal http://${LOCAL}:${WALLET_PORT})`);
    ok();
  }));
}

/* 
 * 4) Benchmark driver
 *  */
async function runBenchmark(){
  const summary = [];

  for (const A of ATTR_COUNTS) {
    for (const R of REVEAL_RATIOS) {
      resetStats();
      console.log(`\n--- Running ${ITER} runs for attrCount=${A}, reveal=${Math.round(R*100)}% ---`);

      for (let i = 0; i < ITER; i++) {
        const r = await getJSON(url(WALLET_PORT, "/run"),{
          method:"POST",
          headers:{ "content-type":"application/json" },
          body: JSON.stringify({ attrCount: A, revealRatio: R })
        });
        if (!r.verified) throw new Error(`Run ${i+1} failed (A=${A}, R=${R})`);
        if ((i+1) % 10 === 0) console.log(`✓ completed ${i+1}/${ITER}`);
      }

      const S = {
        issuer_ms:             stats(M.issuer.t),
        wallet_ms:             stats(M.wallet.t),
        verifier_ms:           stats(M.verifier.t),
        issuer_cpu_ms:         stats(M.issuer.cpu),
        wallet_cpu_ms:         stats(M.wallet.cpu),
        verifier_cpu_ms:       stats(M.verifier.cpu),
        payload_present_bytes: stats(M.payload),
        vc_size_bytes:         stats(M.vcBytes)
      };

      const fmt = (s) => ({
        mean:   s.mean.toFixed(2),
        std:    s.std.toFixed(2),
        median: s.median.toFixed(2),
        min:    s.min.toFixed(2),
        max:    s.max.toFixed(2)
      });
      const rows = {
        "Issuer time (ms)" :  fmt(S.issuer_ms),
        "Wallet time (ms)" :  fmt(S.wallet_ms),
        "Verifier time (ms)": fmt(S.verifier_ms),
        "Issuer CPU (ms)"  :  fmt(S.issuer_cpu_ms),
        "Wallet CPU (ms)"  :  fmt(S.wallet_cpu_ms),
        "Verifier CPU (ms)":  fmt(S.verifier_cpu_ms),
        "Payload bytes"    :  fmt(S.payload_present_bytes),
        "VC bytes"         :  fmt(S.vc_size_bytes)
      };

      console.log(`\n======== Results for attrCount=${A}, reveal=${Math.round(R*100)}% ========\n`);
      console.table(rows);

      writeRow({
        type: "summary",
        impl: IMPL_NAME,
        attrCount: A,
        revealRatio: R,
        metrics: {
          issuer_ms:             S.issuer_ms.mean,
          wallet_ms:             S.wallet_ms.mean,
          verifier_ms:           S.verifier_ms.mean,
          issuer_cpu_ms:         S.issuer_cpu_ms.mean,
          wallet_cpu_ms:         S.wallet_cpu_ms.mean,
          verifier_cpu_ms:       S.verifier_cpu_ms.mean,
          payload_present_bytes: S.payload_present_bytes.mean,
          vc_size_bytes:         S.vc_size_bytes.mean
        }
      });


      summary.push({
        attrCount: A,
        revealPct: Math.round(R*100),
        wallet_ms_mean: rows["Wallet time (ms)"].mean,
        payload_bytes_mean: rows["Payload bytes"].mean,
        vc_bytes_mean: rows["VC bytes"].mean
      });
    }
  }

  if (summary.length) {
    console.log("\n=========== Compact summary (means only) ===========");
    console.table(summary);
  }
  console.log("\nComplexity: O(d) with d = #disclosed attributes");
  process.exit(0);
}

/* Main */
await startIssuer();
await startVerifier();
await startWallet();
await runBenchmark();
