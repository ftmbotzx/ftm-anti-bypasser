# file: api/main.py
import os
import time
import hashlib
import secrets
from typing import Optional, Dict
from fastapi import FastAPI, Request, HTTPException, Body, Form
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from motor.motor_asyncio import AsyncIOMotorClient
import jwt
import asyncio
import base64

# -------- CONFIG ----------
MONGO_URI = os.environ.get("DB_URI", "mongodb+srv://ftm:ftm@cluster0.9a4gw2t.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
SECRET = os.environ.get("SECRET", "ftmbotzx@2025")
BASE_URL = os.environ.get("BASE_URL", "https://ftm-anti-bypasser.vercel.app")
TOKEN_TTL = 120           # seconds
CHALLENGE_TTL = 120
MAX_RETRIES = 4
POW_DIFFICULTY = int(os.environ.get("POW_DIFFICULTY", "18"))  # leading-zero bits (adjust)
RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET")  # optional

# -------- DB ----------
client = AsyncIOMotorClient(MONGO_URI)
db = client.ftm
# collections: shorts, events, challenges, tokens, retries

app = FastAPI(title="FTM Anti-Bypass (Hardened)")

# --------- helpers ----------
def gen_id(n=12):
    return secrets.token_urlsafe(n)[:n]

def sha256_hex(s: str):
    return hashlib.sha256(s.encode()).hexdigest()

def make_jwt(payload: dict):
    payload = payload.copy()
    payload["iat"] = int(time.time())
    payload["exp"] = int(time.time()) + TOKEN_TTL
    return jwt.encode(payload, SECRET, algorithm="HS256")

def decode_jwt(token: str):
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except Exception as e:
        raise HTTPException(status_code=401, detail="invalid_token")

async def ip_from_request(req: Request):
    return req.headers.get("x-forwarded-for", req.client.host if req.client else "")

# --------- Schemas stored in Mongo (implicit) ----------
# shorts: {_id, original, created_at, visits:int}
# events: {short_id, ts, ip, ua, headers, decision, fingerprint}
# challenges: {_id, short_id, ip, ua, created_at, expires_at, pow_target}
# tokens: {token_id, short_id, fp_hash, ip, issued_at, exp, used:false}
# retries: {short_id, ip, count, last_at}

# ---------- PoW helpers ----------
def pow_check(challenge_nonce: str, difficulty_bits: int) -> bool:
    # require SHA256(nonce) to have difficulty_bits leading zero bits
    h = hashlib.sha256(challenge_nonce.encode()).digest()
    # convert to int
    val = int.from_bytes(h, "big")
    return val >> (256 - difficulty_bits) == 0

def pow_make_hint(difficulty_bits: int):
    # server tells client difficulty and a random prefix they must use and find a suffix.
    prefix = secrets.token_urlsafe(8)
    return {"prefix": prefix, "difficulty": difficulty_bits}

# ---------- Endpoints ----------

@app.get("/ftm")
async def create_short(url: str = None):
    if not url:
        raise HTTPException(400, "url required")
    sid = gen_id(10)
    now = int(time.time())
    await db.shorts.insert_one({"_id": sid, "original": url, "created_at": now, "visits": 0})
    return {"short_id": sid, "short_url": f"{BASE_URL}/r/{sid}"}

@app.get("/r/{short_id}")
async def entry(short_id: str, request: Request):
    info = await db.shorts.find_one({"_id": short_id})
    if not info:
        raise HTTPException(404, "short not found")
    ip = await ip_from_request(request)
    ua = request.headers.get("user-agent", "")
    headers = dict(request.headers)

    # increment visits
    await db.shorts.update_one({"_id": short_id}, {"$inc": {"visits": 1}})

    # --- event log ---
    await db.events.insert_one({
        "short_id": short_id, "ts": int(time.time()), "ip": ip,
        "ua": ua, "headers": headers, "decision": "enter"
    })

    # check block/retries
    r = await db.retries.find_one({"short_id": short_id, "ip": ip})
    if r and r.get("count", 0) >= MAX_RETRIES:
        # block for some time
        return JSONResponse(status_code=429, content={"status": "failed_retry", "reason": "max_retries"})

    # cheap checks
    ua_l = ua.lower()
    if any(x in ua_l for x in ["curl", "wget", "python-requests", "httpclient", "bot"]):
        # send challenge
        ch_id = gen_id(12)
        pow_hint = pow_make_hint(POW_DIFFICULTY)
        now = int(time.time())
        await db.challenges.insert_one({
            "_id": ch_id, "short_id": short_id, "ip": ip, "ua": ua, "created_at": now,
            "expires_at": now + CHALLENGE_TTL, "pow_prefix": pow_hint["prefix"], "pow_difficulty": pow_hint["difficulty"]
        })
        return RedirectResponse(url=f"{BASE_URL}/challenge/{ch_id}")

    # if modern headers missing -> challenge (cheap anti-bot)
    sec_headers = any(k.startswith("sec-") for k in headers.keys())
    if not sec_headers:
        ch_id = gen_id(12)
        pow_hint = pow_make_hint(POW_DIFFICULTY)
        now = int(time.time())
        await db.challenges.insert_one({
            "_id": ch_id, "short_id": short_id, "ip": ip, "ua": ua, "created_at": now,
            "expires_at": now + CHALLENGE_TTL, "pow_prefix": pow_hint["prefix"], "pow_difficulty": pow_hint["difficulty"]
        })
        return RedirectResponse(url=f"{BASE_URL}/challenge/{ch_id}")

    # Looks OK -> issue one-time token
    # We still ask client to provide a light fingerprint (via JS) before issuing token.
    # If no fingerprint yet, redirect to challenge that will compute fingerprint quickly.
    # We'll require the shortener to call /check_token server-side before paying.

    # create ephemeral challenge anyway to compute fp from client for binding
    ch_id = gen_id(12)
    pow_hint = pow_make_hint(POW_DIFFICULTY)
    now = int(time.time())
    await db.challenges.insert_one({
        "_id": ch_id, "short_id": short_id, "ip": ip, "ua": ua, "created_at": now,
        "expires_at": now + CHALLENGE_TTL, "pow_prefix": pow_hint["prefix"], "pow_difficulty": pow_hint["difficulty"]
    })
    return RedirectResponse(url=f"{BASE_URL}/challenge/{ch_id}")


# challenge page: client must compute pow + fingerprint, optionally captcha
@app.get("/challenge/{ch_id}")
async def challenge_page(ch_id: str):
    ch = await db.challenges.find_one({"_id": ch_id})
    if not ch:
        return HTMLResponse("<h3>Invalid or expired challenge</h3>", status_code=400)
    # serve HTML that:
    # - computes a fingerprint (canvas hash + timezone + screen)
    # - runs PoW: find suffix so sha256(prefix + "." + suffix) has difficulty leading zeros
    # - POST to /verify with {challenge_id, fp_hash, pow_nonce, recaptcha_token?}
    prefix = ch["pow_prefix"]
    difficulty = ch["pow_difficulty"]
    html = f"""
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Checking your browser</title></head>
<body>
  <p>Verifying — please wait...</p>
  <script>
  // fingerprint (simple)
  function getFP(){
    const vals = [
      navigator.userAgent,
      navigator.platform,
      Intl.DateTimeFormat().resolvedOptions().timeZone || "",
      screen.width + "x" + screen.height,
      navigator.language || ""
    ];
    // canvas fingerprint
    try {{
      const c = document.createElement('canvas');
      const ctx = c.getContext('2d');
      ctx.fillStyle = 'rgb(120,14,0)';
      ctx.fillRect(2,2,10,10);
      ctx.font = '11px Arial';
      ctx.fillText('ftm-check',2,12);
      vals.push(c.toDataURL());
    }} catch(e){{ vals.push('no_canvas'); }}
    return btoa(vals.join('||'));
  }
  // simple SHA-256
  async function sha256(text){ 
    const data = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  (async ()=>{{
    const prefix = "{prefix}";
    const difficulty = {difficulty};
    const fp = getFP();
    const fp_hash = await sha256(fp);

    // Proof-of-work: find suffix with required leading zero bits
    // We'll check by requiring first N hex characters to be zeros (approx)
    // Convert difficulty bits -> hex zeros approx:
    const hexZeros = Math.floor(difficulty / 4);
    let nonce = 0;
    let candidate;
    let hash;
    while(true){{
      candidate = prefix + '.' + nonce;
      hash = await sha256(candidate);
      if(hash.startsWith('{"0".repeat(hexZeros)}'.replace('{{}}','')) || hash.slice(0,hexZeros) === '0'.repeat(hexZeros)) break;
      nonce++;
      // protect device by short-circuit if too long
      if(nonce % 10000 === 0) await new Promise(r=>setTimeout(r,1));
    }}
    // submit
    fetch("{BASE_URL}/verify", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{challenge_id: "{ch_id}", fp_hash: fp_hash, pow_nonce: nonce}})
    }}).then(r=>r.json()).then(j=>{
      if(j.ok && j.action_url) window.location = j.action_url;
      else document.body.innerHTML = "<h3>Verification failed</h3>";
    }}).catch(e=>document.body.innerHTML = "<h3>Error</h3>");
  }})();
  </script>
</body>
</html>
"""
    return HTMLResponse(html)


@app.post("/verify")
async def verify(data: Dict = Body(...)):
    ch_id = data.get("challenge_id")
    fp_hash = data.get("fp_hash")
    pow_nonce = str(data.get("pow_nonce", ""))
    if not ch_id or not fp_hash or pow_nonce is None:
        return JSONResponse(status_code=400, content={"ok": False, "error": "missing"})

    ch = await db.challenges.find_one({"_id": ch_id})
    if not ch:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_challenge"})

    # check expiry
    if ch["expires_at"] < int(time.time()):
        return JSONResponse(status_code=400, content={"ok": False, "error": "expired"})

    # check PoW
    candidate = f"{ch['pow_prefix']}.{pow_nonce}"
    if not pow_check(candidate, ch["pow_difficulty"]):
        # increase retry counter
        await db.retries.update_one({"short_id": ch["short_id"], "ip": ch["ip"]},
                                    {"$inc": {"count": 1}, "$set": {"last_at": int(time.time())}},
                                    upsert=True)
        return JSONResponse(status_code=400, content={"ok": False, "error": "pow_failed"})

    # Passed -> issue one-time token stored in db
    token_id = gen_id(16)
    token_payload = {"token_id": token_id, "short_id": ch["short_id"], "fp_hash": fp_hash, "ip": ch["ip"]}
    token_jwt = make_jwt(token_payload)
    now = int(time.time())
    await db.tokens.insert_one({
        "token_id": token_id, "short_id": ch["short_id"], "fp_hash": fp_hash,
        "ip": ch["ip"], "issued_at": now, "exp": now + TOKEN_TTL, "used": False
    })
    # remove challenge doc (one-time)
    await db.challenges.delete_one({"_id": ch_id})

    # build redirect URL (original + ftm_token)
    short = await db.shorts.find_one({"_id": ch["short_id"]})
    if not short: return JSONResponse(status_code=500, content={"ok": False})
    target = short["original"]
    action_url = f"{target}&ftm_token={token_jwt}" if "?" in target else f"{target}?ftm_token={token_jwt}"

    # log event
    await db.events.insert_one({"short_id": ch["short_id"], "ts": now, "ip": ch["ip"],
                                "ua": ch["ua"], "decision": "verified", "fp_hash": fp_hash})
    return {"ok": True, "action_url": action_url, "token": token_jwt}


@app.post("/check_token")
async def check_token(payload: Dict = Body(...)):
    """
    Called by the shortener server before counting payout.
    Payload: { token: <jwt>, short_id: <id> }
    Response: { ok: true, reason: ... }
    """
    token = payload.get("token")
    short_id = payload.get("short_id")
    if not token or not short_id:
        raise HTTPException(400, "token & short_id required")
    # decode & verify jwt
    try:
        data = decode_jwt(token)
    except Exception:
        raise HTTPException(401, "invalid token")

    token_id = data.get("token_id")
    if data.get("short_id") != short_id:
        raise HTTPException(401, "short_id mismatch")

    # find token doc and ensure unused
    doc = await db.tokens.find_one({"token_id": token_id})
    if not doc:
        raise HTTPException(401, "token not found")
    if doc.get("used"):
        raise HTTPException(401, "token already used")
    if doc.get("exp", 0) < int(time.time()):
        raise HTTPException(401, "token expired")

    # mark used (atomic)
    res = await db.tokens.update_one({"token_id": token_id, "used": False}, {"$set": {"used": True, "consumed_at": int(time.time())}})
    if res.modified_count != 1:
        # race or already used
        raise HTTPException(401, "token race/used")

    # Optional: check other heuristics (e.g., many tokens from same fp across IPs)
    return {"ok": True, "msg": "valid"}

# health
@app.get("/health")
async def health():
    return {"ok": True}
