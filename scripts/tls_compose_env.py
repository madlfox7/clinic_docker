"""Run scripts/tls_check.sh with the values Compose will really use."""
import json
import os
import sys

config = json.load(sys.stdin)
services = config["services"]
proxy = services["proxy"]
env = dict(os.environ)
proxy_env = proxy.get("environment") or {}
api_env = services.get("api", {}).get("environment") or {}
for name, value in (("PUBLIC_BASE_URL", proxy_env.get("PUBLIC_BASE_URL")),
                    ("CLINIC_TLS_MODE", proxy_env.get("CLINIC_TLS_MODE")),
                    ("CLINIC_PUBLIC_TUNNEL", proxy_env.get("CLINIC_PUBLIC_TUNNEL")),
                    ("SESSION_HTTPS_ONLY", api_env.get("SESSION_HTTPS_ONLY"))):
    if value is not None:
        env[name] = str(value)
for target, name in ((8080, "CLINIC_PROXY_PORT"), (8443, "CLINIC_PROXY_TLS_PORT")):
    published = [str(p.get("published", "")) for p in proxy.get("ports") or [] if int(p["target"]) == target]
    if len(published) != 1:
        sys.exit(f"error   proxy must publish container port {target} exactly once, found {len(published)}")
    env[name] = published[0]
script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tls_check.sh")
os.execve("/bin/sh", ["sh", script, *sys.argv[1:]], env)
