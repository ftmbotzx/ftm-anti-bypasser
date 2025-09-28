
MONGO_URI = os.environ.get("DB_URI", "")
SECRET = os.environ.get("SECRET", "ftmbotzx@2025")
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
SECRET = os.environ.get("SECRET", "ftm-random-secret-abc123xyz789")

if not MONGO_URI or not SECRET:
    raise ValueError("DB_URI and SECRET environment variables must be set")
BASE_URL = os.environ.get("BASE_URL", "https://ftm-anti-bypasser.vercel.app")
TOKEN_TTL = 120           # seconds
CHALLENGE_TTL = 120
MAX_RETRIES = 4
POW_DIFFICULTY = int(os.environ.get("POW_DIFFICULTY", "12"))  # Reduced from 18 to 12 bits for faster computation
RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET", "6Lc4INgrAAAAAIsGZCailUpP3KDq_t0kzXlPTAb2")  # optional

# -------- DB ----------
# Add shorter timeouts for better user experience
client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000)
db = client.ftm
# collections: shorts, events, challenges, tokens, retries

# DB helper with error handling
async def safe_db_operation(operation, error_message="Database unavailable"):
    try:
        return await operation
    except Exception as e:
        print(f"DB Error: {e}")
        return None

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
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token_expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid_token")
    except Exception as e:
        raise HTTPException(status_code=401, detail="invalid_token")

async def ip_from_request(req: Request):
    return req.headers.get("x-forwarded-for", req.client.host if req.client else "")

# Helper to get base URL from request instead of hard-coded
def get_base_url(request: Request) -> str:
    return f"{request.url.scheme}://{request.url.netloc}"

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
async def create_short(url: Optional[str] = None, request: Request = None):
    if not url:
        raise HTTPException(400, "url required")
    sid = gen_id(10)
    now = int(time.time())
    
    # Use safe DB operation with timeout
    result = await safe_db_operation(
        db.shorts.insert_one({"_id": sid, "original": url, "created_at": now, "visits": 0})
    )
    
    if result is None:
        raise HTTPException(503, "Database temporarily unavailable. Please try again.")
    
    base_url = get_base_url(request)
    return {"short_id": sid, "short_url": f"{base_url}/r/{sid}"}

@app.get("/r/{short_id}")
async def entry(short_id: str, request: Request):
    # Safe DB operation with error handling
    info = await safe_db_operation(db.shorts.find_one({"_id": short_id}))
    if info is None:
        return HTMLResponse(
            "<h3>Service temporarily unavailable</h3><p>Please try again in a few moments.</p>", 
            status_code=503
        )
    if not info:
        raise HTTPException(404, "short not found")
        
    ip = await ip_from_request(request)
    ua = request.headers.get("user-agent", "")
    headers = dict(request.headers)

    # increment visits (safe operation)
    await safe_db_operation(db.shorts.update_one({"_id": short_id}, {"$inc": {"visits": 1}}))

    # --- event log (safe operation) ---
    await safe_db_operation(db.events.insert_one({
        "short_id": short_id, "ts": int(time.time()), "ip": ip,
        "ua": ua, "headers": headers, "decision": "enter"
    }))

    # check block/retries (safe operation)
    r = await safe_db_operation(db.retries.find_one({"short_id": short_id, "ip": ip}))
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
        challenge_result = await safe_db_operation(db.challenges.insert_one({
            "_id": ch_id, "short_id": short_id, "ip": ip, "ua": ua, "created_at": now,
            "expires_at": now + CHALLENGE_TTL, "pow_prefix": pow_hint["prefix"], "pow_difficulty": pow_hint["difficulty"]
        }))
        
        if challenge_result is None:
            return HTMLResponse(
                "<h3>Service temporarily unavailable</h3><p>Please try again in a few moments.</p>", 
                status_code=503
            )
            
        base_url = get_base_url(request)
        return RedirectResponse(url=f"{base_url}/challenge/{ch_id}")

    # if modern headers missing -> challenge (cheap anti-bot)
    sec_headers = any(k.startswith("sec-") for k in headers.keys())
    if not sec_headers:
        ch_id = gen_id(12)
        pow_hint = pow_make_hint(POW_DIFFICULTY)
        now = int(time.time())
        challenge_result = await safe_db_operation(db.challenges.insert_one({
            "_id": ch_id, "short_id": short_id, "ip": ip, "ua": ua, "created_at": now,
            "expires_at": now + CHALLENGE_TTL, "pow_prefix": pow_hint["prefix"], "pow_difficulty": pow_hint["difficulty"]
        }))
        
        if challenge_result is None:
            return HTMLResponse(
                "<h3>Service temporarily unavailable</h3><p>Please try again in a few moments.</p>", 
                status_code=503
            )
            
        base_url = get_base_url(request)
        return RedirectResponse(url=f"{base_url}/challenge/{ch_id}")

    # Looks OK -> issue one-time token
    # We still ask client to provide a light fingerprint (via JS) before issuing token.
    # If no fingerprint yet, redirect to challenge that will compute fingerprint quickly.
    # We'll require the shortener to call /check_token server-side before paying.

    # create ephemeral challenge anyway to compute fp from client for binding
    ch_id = gen_id(12)
    pow_hint = pow_make_hint(POW_DIFFICULTY)
    now = int(time.time())
    
    challenge_result = await safe_db_operation(db.challenges.insert_one({
        "_id": ch_id, "short_id": short_id, "ip": ip, "ua": ua, "created_at": now,
        "expires_at": now + CHALLENGE_TTL, "pow_prefix": pow_hint["prefix"], "pow_difficulty": pow_hint["difficulty"]
    }))
    
    if challenge_result is None:
        return HTMLResponse(
            "<h3>Service temporarily unavailable</h3><p>Please try again in a few moments.</p>", 
            status_code=503
        )
        
    base_url = get_base_url(request)
    return RedirectResponse(url=f"{base_url}/challenge/{ch_id}")


# challenge page: client must compute pow + fingerprint, optionally captcha
@app.get("/challenge/{ch_id}")
async def challenge_page(ch_id: str, request: Request):
    # Safe DB operation with proper error handling
    ch = await safe_db_operation(db.challenges.find_one({"_id": ch_id}))
    
    if ch is None:
        # Database unavailable - show friendly error
        return HTMLResponse(
            "<h3>Service temporarily unavailable</h3><p>Please try again in a few moments.</p>", 
            status_code=503
        )
    
    if not ch:
        return HTMLResponse("<h3>Invalid or expired challenge</h3>", status_code=400)
    # serve HTML that:
    # - computes a fingerprint (canvas hash + timezone + screen)
    # - runs PoW: find suffix so sha256(prefix + "." + suffix) has difficulty leading zeros
    # - POST to /verify with {challenge_id, fp_hash, pow_nonce, recaptcha_token?}
    prefix = ch["pow_prefix"]
    difficulty = ch["pow_difficulty"]
    
    # Improved HTML template with progress indicator and optimized PoW
    html_template = """<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Checking your browser</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; text-align: center; }
        .progress { margin: 20px 0; }
        .progress-bar { width: 300px; height: 20px; background: #f0f0f0; border-radius: 10px; margin: 10px auto; }
        .progress-fill { height: 100%; background: #4CAF50; border-radius: 10px; width: 0%; transition: width 0.3s; }
    </style>
</head>
<body>
    <h2>Verifying your browser</h2>
    <p id="status">Please wait while we verify your browser...</p>
    <div class="progress">
        <div class="progress-bar">
            <div class="progress-fill" id="progress"></div>
        </div>
        <p id="progress-text">0%</p>
    </div>
    
    <script>
    // Update status and progress
    function updateProgress(percent, text) {
        document.getElementById('progress').style.width = percent + '%';
        document.getElementById('progress-text').textContent = Math.round(percent) + '%';
        document.getElementById('status').textContent = text;
    }

    // fingerprint (simple)
    function getFP(){
        var vals = [
            navigator.userAgent,
            navigator.platform,
            Intl.DateTimeFormat().resolvedOptions().timeZone || "",
            screen.width + "x" + screen.height,
            navigator.language || ""
        ];
        // canvas fingerprint
        try {
            var c = document.createElement('canvas');
            var ctx = c.getContext('2d');
            ctx.fillStyle = 'rgb(120,14,0)';
            ctx.fillRect(2,2,10,10);
            ctx.font = '11px Arial';
            ctx.fillText('ftm-check',2,12);
            vals.push(c.toDataURL());
        } catch(e){ vals.push('no_canvas'); }
        return btoa(vals.join('||'));
    }

    // Optimized SHA-256 using built-in crypto API
    async function sha256(text){ 
        var data = new TextEncoder().encode(text);
        var hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
    }

    // Check if hash meets difficulty requirement
    function checkPowDifficulty(hashHex, difficultyBits) {
        // Convert hex to binary and check leading zeros
        var binary = '';
        for (var i = 0; i < hashHex.length; i++) {
            binary += parseInt(hashHex[i], 16).toString(2).padStart(4, '0');
        }
        // Count leading zeros
        var leadingZeros = 0;
        for (var i = 0; i < binary.length; i++) {
            if (binary[i] === '0') leadingZeros++;
            else break;
        }
        return leadingZeros >= difficultyBits;
    }

    (async ()=>{
        try {
            var prefix = "PREFIX_PLACEHOLDER";
            var difficulty = DIFFICULTY_PLACEHOLDER;
            updateProgress(10, "Computing browser fingerprint...");
            
            var fp = getFP();
            var fp_hash = await sha256(fp);
            updateProgress(20, "Starting proof-of-work computation...");

            // Proof-of-work with progress tracking and timeout protection
            var nonce = 0;
            var candidate;
            var hash;
            var startTime = Date.now();
            var maxTime = 30000; // 30 second timeout
            var lastProgress = Date.now();
            
            while(true){
                candidate = prefix + '.' + nonce;
                hash = await sha256(candidate);
                
                if(checkPowDifficulty(hash, difficulty)) {
                    updateProgress(90, "Proof-of-work complete! Verifying...");
                    break;
                }
                
                nonce++;
                
                // Update progress every 1000 iterations or every second
                if(nonce % 1000 === 0 || Date.now() - lastProgress > 1000) {
                    var elapsed = Date.now() - startTime;
                    if(elapsed > maxTime) {
                        updateProgress(0, "Verification timeout. Please refresh and try again.");
                        return;
                    }
                    
                    // Estimate progress based on difficulty (very rough)
                    var expectedIterations = Math.pow(2, difficulty - 4); // rough estimate
                    var progress = Math.min(80, 20 + (nonce / expectedIterations) * 60);
                    updateProgress(progress, `Computing proof-of-work... (${nonce} attempts)`);
                    lastProgress = Date.now();
                    
                    // Yield control to prevent UI freezing
                    if(nonce % 1000 === 0) await new Promise(r=>setTimeout(r,1));
                }
            }
            
            updateProgress(95, "Submitting verification...");
            
            // Submit verification
            fetch("/verify", {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    challenge_id: "CHALLENGE_ID_PLACEHOLDER", 
                    fp_hash: fp_hash, 
                    pow_nonce: nonce
                })
            }).then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            }).then(j=>{
                if(j.ok && j.action_url) {
                    updateProgress(100, "Verification successful! Redirecting...");
                    setTimeout(() => window.location.href = j.action_url, 500);
                } else {
                    updateProgress(0, "Verification failed: " + (j.error || "Unknown error"));
                }
            }).catch(e=>{
                updateProgress(0, "Network error: " + e.message);
                console.error("Verification error:", e);
                // Show retry option after 3 seconds
                setTimeout(() => {
                    updateProgress(0, "Verification failed. Please refresh the page to try again.");
                }, 3000);
            });
            
        } catch(error) {
            updateProgress(0, "Error during verification: " + error.message);
            console.error(error);
        }
    })();
    </script>
</body>
</html>"""
    
    # Replace placeholders with actual values - use dynamic base URL
    base_url = get_base_url(request)
    html = html_template.replace("PREFIX_PLACEHOLDER", prefix)
    html = html.replace("DIFFICULTY_PLACEHOLDER", str(difficulty))
    html = html.replace("BASE_URL_PLACEHOLDER", base_url)
    html = html.replace("CHALLENGE_ID_PLACEHOLDER", ch_id)
    
    return HTMLResponse(html)


@app.post("/verify")
async def verify(data: Dict = Body(...)):
    ch_id = data.get("challenge_id")
    fp_hash = data.get("fp_hash")
    pow_nonce_raw = data.get("pow_nonce")
    
    # Improved input validation
    if not ch_id or not fp_hash or pow_nonce_raw is None or pow_nonce_raw == "":
        return JSONResponse(status_code=400, content={"ok": False, "error": "missing_or_empty"})
    
    pow_nonce = str(pow_nonce_raw)

    # Safe DB operation
    ch = await safe_db_operation(db.challenges.find_one({"_id": ch_id}))
    
    if ch is None:
        return JSONResponse(status_code=503, content={"ok": False, "error": "service_unavailable"})
        
    if not ch:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid_challenge"})

    # check expiry
    if ch["expires_at"] < int(time.time()):
        return JSONResponse(status_code=400, content={"ok": False, "error": "expired"})

    # check PoW
    candidate = f"{ch['pow_prefix']}.{pow_nonce}"
    if not pow_check(candidate, ch["pow_difficulty"]):
        # increase retry counter (safe operation)
        await safe_db_operation(
            db.retries.update_one({"short_id": ch["short_id"], "ip": ch["ip"]},
                                  {"$inc": {"count": 1}, "$set": {"last_at": int(time.time())}},
                                  upsert=True)
        )
        return JSONResponse(status_code=400, content={"ok": False, "error": "pow_failed"})

    # Passed -> issue one-time token stored in db
    token_id = gen_id(16)
    token_payload = {"token_id": token_id, "short_id": ch["short_id"], "fp_hash": fp_hash, "ip": ch["ip"]}
    token_jwt = make_jwt(token_payload)
    now = int(time.time())
    
    # Safe DB operations for token creation
    token_result = await safe_db_operation(
        db.tokens.insert_one({
            "token_id": token_id, "short_id": ch["short_id"], "fp_hash": fp_hash,
            "ip": ch["ip"], "issued_at": now, "exp": now + TOKEN_TTL, "used": False
        })
    )
    
    if token_result is None:
        return JSONResponse(status_code=503, content={"ok": False, "error": "service_unavailable"})
    
    # remove challenge doc (one-time)
    await safe_db_operation(db.challenges.delete_one({"_id": ch_id}))

    # build redirect URL (original + ftm_token)
    short = await safe_db_operation(db.shorts.find_one({"_id": ch["short_id"]}))
    if short is None:
        return JSONResponse(status_code=503, content={"ok": False, "error": "service_unavailable"})
    if not short: 
        return JSONResponse(status_code=500, content={"ok": False})
    target = short["original"]
    action_url = f"{target}&ftm_token={token_jwt}" if "?" in target else f"{target}?ftm_token={token_jwt}"

    # log event (safe operation)
    await safe_db_operation(
        db.events.insert_one({"short_id": ch["short_id"], "ts": now, "ip": ch["ip"],
                              "ua": ch["ua"], "decision": "verified", "fp_hash": fp_hash})
    )
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
        raise HTTPException(401, "token short_id mismatch")

    # Check db token (safe operation)
    tk = await safe_db_operation(db.tokens.find_one({"token_id": token_id}))
    if tk is None:
        raise HTTPException(503, "Database temporarily unavailable")
    if not tk:
        raise HTTPException(401, "token not found in db")
    if tk["used"]:
        raise HTTPException(401, "token already used")
    if tk["exp"] < int(time.time()):
        raise HTTPException(401, "token expired in db")
    
    # Mark as used (one-time) - safe operation
    await safe_db_operation(
        db.tokens.update_one({"token_id": token_id}, {"$set": {"used": True}})
    )
    
    # Log successful check (safe operation)
    await safe_db_operation(
        db.events.insert_one({
            "short_id": short_id, "ts": int(time.time()), "ip": tk["ip"],
            "decision": "token_verified", "token_id": token_id
        })
    )
    
    return {"ok": True, "reason": "valid_token"}


# Health check endpoint
@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": int(time.time())}


# Root endpoint with basic info
@app.get("/")
async def root():
    return {
        "service": "FTM Anti-Bypass API",
        "version": "2.0",
        "endpoints": {
            "create_short": "GET /ftm?url=<url>",
            "access_short": "GET /r/<short_id>",
            "check_token": "POST /check_token",
            "health": "GET /health"
        }
    }
