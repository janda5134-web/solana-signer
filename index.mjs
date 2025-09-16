import express from "express";
import cors from "cors";
import crypto from "crypto";
import fetch from "node-fetch";
import bs58 from "bs58";
import { Connection, Keypair, VersionedTransaction } from "@solana/web3.js";

const app = express();
app.use(cors());
app.use(express.json({limit:"1mb"}));

const {
  HMAC_SECRET = "",
  RPC_URL = "https://api.devnet.solana.com",
  TRADER_SECRET_BASE58 = "",
  TRADER_SECRET_JSON = "",
  JUPITER_BASE = "https://quote-api.jup.ag",
  PRIORITIZATION_FEE_LAMPORTS = ""
} = process.env;

// تحميل المفتاح الخاص (يدعم Base58 أو JSON)
function loadKeypair() {
  if (TRADER_SECRET_BASE58) {
    return Keypair.fromSecretKey(Buffer.from(bs58.decode(TRADER_SECRET_BASE58)));
  }
  if (TRADER_SECRET_JSON) {
    const arr = JSON.parse(TRADER_SECRET_JSON);
    return Keypair.fromSecretKey(Uint8Array.from(arr));
  }
  throw new Error("No private key provided");
}

function verifyHmac(body, ts, sign) {
  const mac = crypto.createHmac("sha256", HMAC_SECRET).update(body+ts).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(sign)); }
  catch { return false; }
}

app.get("/health", (_, res) => res.json({ ok: true }));

app.post("/trade", async (req, res) => {
  try {
    const raw = JSON.stringify(req.body);
    const ts = req.header("X-Timestamp");
    const sig = req.header("X-Sign");
    if (!HMAC_SECRET || !ts || !sig || !verifyHmac(raw, ts, sig)) {
      return res.status(401).json({ ok:false, error:"bad_hmac" });
    }

    const { mintOut, amountSol } = req.body;
    if (!mintOut || !amountSol) return res.status(400).json({ ok:false, error:"bad_body" });

    const kp = loadKeypair();
    const userPubkey = kp.publicKey.toBase58();
    const connection = new Connection(RPC_URL, "confirmed");

    const inputMint = "So11111111111111111111111111111111111111112"; // wSOL
    const lamports = Math.floor(amountSol * 1_000_000_000);

    // Quote
    const q = await fetch(`${JUPITER_BASE}/v6/quote?inputMint=${inputMint}&outputMint=${mintOut}&amount=${lamports}&slippageBps=50`);
    if (!q.ok) return res.status(500).json({ ok:false, error:"quote_failed" });
    const quote = await q.json();

    // Swap TX
    const s = await fetch(`${JUPITER_BASE}/v6/swap`, {
      method:"POST",
      headers:{ "content-type":"application/json" },
      body: JSON.stringify({
        quoteResponse: quote,
        userPublicKey: userPubkey,
        wrapAndUnwrapSol: true,
        prioritizationFeeLamports: PRIORITIZATION_FEE_LAMPORTS ? Number(PRIORITIZATION_FEE_LAMPORTS) : undefined
      })
    });
    if (!s.ok) return res.status(500).json({ ok:false, error:"swap_prep_failed" });
    const swap = await s.json();

    const rawTx = Buffer.from(swap.swapTransaction, "base64");
    const tx = VersionedTransaction.deserialize(rawTx);
    tx.sign([kp]);
    const sigTx = await connection.sendRawTransaction(tx.serialize(), { skipPreflight:false, maxRetries:3 });
    return res.json({ ok:true, tx:sigTx, pubkey: userPubkey });
  } catch (e) {
    return res.status(500).json({ ok:false, error: String(e) });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log("signer on", port));
