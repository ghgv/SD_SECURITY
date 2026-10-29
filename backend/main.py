
import os
import json
import re
import secrets
import threading
from pathlib import Path
from urllib.parse import urlparse
from html import escape

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Nubeware SD Security")

DATA = Path("/home/ubuntu/sd_security/policy.json")
LOCK = threading.RLock()
basic = HTTPBasic()

ADMIN_USER = os.environ["ADMIN_USER"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
DEVICE_USER = os.environ["DEVICE_USER"]
DEVICE_PASSWORD = os.environ["DEVICE_PASSWORD"]

DEFAULT = {
    "revision": 0,
    "blocked_domains": [],
    "wifi": {
        "enabled": True,
        "ssid": "Nubeware-Security",
        "password": "",
        "channel": 6,
        "encryption": "psk2"
    }
}


def check_user(credentials, username, password):
    if not (
        secrets.compare_digest(credentials.username, username)
        and secrets.compare_digest(credentials.password, password)
    ):
        raise HTTPException(
            401,
            "Credenciales invalidas",
            headers={"WWW-Authenticate": "Basic realm=\"Nubeware\""}
        )


def admin_auth(c: HTTPBasicCredentials = Depends(basic)):
    check_user(c, ADMIN_USER, ADMIN_PASSWORD)


def device_auth(c: HTTPBasicCredentials = Depends(basic)):
    check_user(c, DEVICE_USER, DEVICE_PASSWORD)


def read_policy():
    policy = (
        json.loads(DATA.read_text(encoding="utf-8"))
        if DATA.exists()
        else {}
    )

    # Compatibilidad con políticas anteriores
    policy.setdefault("revision", 0)
    policy.setdefault("blocked_domains", [])

    # Agregar configuración Wi-Fi si no existe
    if not isinstance(policy.get("wifi"), dict):
        policy["wifi"] = {}

    for key, value in DEFAULT["wifi"].items():
        policy["wifi"].setdefault(key, value)

    return policy


def save_policy(data):
    temp = DATA.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    temp.replace(DATA)


def domain_from_url(url):
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    domain = urlparse(url).hostname or ""
    domain = domain.rstrip(".")

    if not re.fullmatch(
        r"(?=.{1,253}$)"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
        domain
    ):
        raise HTTPException(400, "Dominio invalido")

    return domain


class BlockRequest(BaseModel):
    url: str


class WiFiRequest(BaseModel):
    enabled: bool
    ssid: str = Field(min_length=1, max_length=32)
    password: str | None = None
    channel: int = Field(ge=1, le=11)


@app.get("/")
def root():
    return {"service": "Nubeware SD Security", "status": "ok"}


@app.get("/firewall/policy", dependencies=[Depends(device_auth)])
def get_policy():
    with LOCK:
        return read_policy()


@app.get("/admin/policy", dependencies=[Depends(admin_auth)])
def admin_policy():
    with LOCK:
        policy = read_policy()
        # No devolver la clave Wi-Fi al navegador
        policy["wifi"]["password"] = ""
        return policy


@app.post("/admin/wifi", dependencies=[Depends(admin_auth)])
def update_wifi(body: WiFiRequest):
    if any(ord(c) < 32 for c in body.ssid):
        raise HTTPException(400, "SSID invalido")

    with LOCK:
        policy = read_policy()
        old = policy["wifi"]
        password = body.password if body.password else old["password"]

        if body.enabled and not 8 <= len(password.encode()) <= 63:
            raise HTTPException(400, "WPA2 requiere clave de 8 a 63 bytes")

        if any(ord(c) < 32 or ord(c) > 126 for c in password):
            raise HTTPException(400, "Utiliza una clave WPA2 ASCII imprimible")

        new = {
            "enabled": body.enabled,
            "ssid": body.ssid,
            "password": password,
            "channel": body.channel,
            "encryption": "psk2"
        }

        if new != old:
            policy["wifi"] = new
            policy["revision"] += 1
            save_policy(policy)

        return {"ok": True, "revision": policy["revision"]}


@app.post("/admin/firewall/block", dependencies=[Depends(admin_auth)])
def block_domain(body: BlockRequest):
    domain = domain_from_url(body.url)
    with LOCK:
        policy = read_policy()
        if domain not in policy["blocked_domains"]:
            policy["blocked_domains"].append(domain)
            policy["blocked_domains"].sort()
            policy["revision"] += 1
            save_policy(policy)

        return {"ok": True, "domain": domain,
                "revision": policy["revision"]}


@app.delete("/admin/firewall/block/{domain}",
            dependencies=[Depends(admin_auth)])
def unblock_domain(domain: str):
    domain = domain_from_url(domain)
    with LOCK:
        policy = read_policy()
        if domain not in policy["blocked_domains"]:
            raise HTTPException(404, "Dominio no encontrado")

        policy["blocked_domains"].remove(domain)
        policy["revision"] += 1
        save_policy(policy)

        return {"ok": True, "revision": policy["revision"]}


@app.get("/admin", response_class=HTMLResponse,
         dependencies=[Depends(admin_auth)])
def admin_page():
    return """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nubeware SD Security</title>
<style>
body{font-family:system-ui;background:#f4f6fa;color:#172334;
     max-width:680px;margin:35px auto;padding:15px}
section{background:white;padding:24px;border-radius:12px;
        margin-bottom:16px;border:1px solid #dce2ea}
label{display:block;margin:15px 0 5px;font-weight:600}
input,select{box-sizing:border-box;width:100%;padding:11px;
             border:1px solid #bbc5d1;border-radius:7px}
input[type=checkbox]{width:auto}
button{background:#245fa3;color:white;border:0;border-radius:7px;
       padding:11px 18px;cursor:pointer;margin-top:16px}
.delete{background:#a52d39;margin:0;padding:5px 10px}
li{display:flex;justify-content:space-between;align-items:center;
   margin:8px 0;gap:10px}
#msg{white-space:pre-wrap}
</style>
</head>
<body>
<h1>Nubeware SD Security</h1>
<p>Gestión central del TL-WR940N v6</p>
<section>
<h2>Red inalámbrica</h2>
<label><input id="enabled" type="checkbox"> Wi-Fi habilitado</label>
<label>SSID</label><input id="ssid" maxlength="32">
<label>Contraseña WPA2</label>
<input id="password" type="password" autocomplete="new-password"
       placeholder="Dejar vacío para conservar la actual">
<label>Canal 2.4 GHz</label>
<select id="channel"></select>
<button onclick="saveWiFi()">Publicar configuración Wi-Fi</button>
</section>
<section>
<h2>Dominios bloqueados</h2>
<input id="domain" placeholder="facebook.com">
<button onclick="blockDomain()">Agregar bloqueo</button>
<ul id="domains"></ul>
</section>
<section>
<strong id="revision"></strong>
<p id="msg"></p>
</section>
<script>
const base = location.pathname.replace(/\\/admin\\/?$/, "");
const el = id => document.getElementById(id);
for(let i=1;i<=11;i++) el("channel").add(new Option(i,i));

async function request(path, options={}) {
    const response = await fetch(base + path, {
        ...options,
        headers: {"Content-Type":"application/json",
                  ...(options.headers||{})},
        cache: "no-store"
    });
    if(!response.ok) throw Error(await response.text());
    return response.json();
}

async function refresh() {
    try {
        const p = await request("/admin/policy");
        el("enabled").checked = p.wifi.enabled;
        el("ssid").value = p.wifi.ssid;
        el("channel").value = p.wifi.channel;
        el("revision").textContent = "Revisión " + p.revision;
        const list = el("domains");
        list.replaceChildren();
        for(const domain of p.blocked_domains) {
            const li = document.createElement("li");
            const span = document.createElement("span");
            span.textContent = domain;
            const btn = document.createElement("button");
            btn.className = "delete";
            btn.textContent = "Eliminar";
            btn.onclick = () => removeDomain(domain);
            li.append(span, btn);
            list.append(li);
        }
    } catch(e) {el("msg").textContent = e.message}
}

async function saveWiFi() {
    try {
        await request("/admin/wifi", {
            method:"POST",
            body:JSON.stringify({
                enabled:el("enabled").checked,
                ssid:el("ssid").value,
                password:el("password").value || null,
                channel:Number(el("channel").value)
            })
        });
        el("password").value = "";
        el("msg").textContent = "Configuración publicada";
        await refresh();
    } catch(e) {el("msg").textContent = e.message}
}

async function blockDomain() {
    try {
        await request("/admin/firewall/block", {
            method:"POST",
            body:JSON.stringify({url:el("domain").value})
        });
        el("domain").value = "";
        await refresh();
    } catch(e) {el("msg").textContent = e.message}
}

async function removeDomain(domain) {
    try {
        await request("/admin/firewall/block/"+encodeURIComponent(domain),
                      {method:"DELETE"});
        await refresh();
    } catch(e) {el("msg").textContent = e.message}
}
refresh();
</script>
</body>
</html>
"""
