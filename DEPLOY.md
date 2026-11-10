# Deploying SURL on a free-tier EC2 instance

Target: one `t3.micro` (1 GB RAM, 8 GB+ gp3) running Ubuntu. Sized for a demo with
a handful of visitors; scans run one browser at a time and queue behind that.

## Flow

push to `deploy` -> GitHub Actions (ruff, pytest, image build + `/health` smoke test)
-> image pushed to `ghcr.io/joeljohngeorge8080/surl:deploy`
-> `surl-deploy.timer` on the instance pulls it within ~1 minute and restarts the stack
-> nginx (host) terminates TLS and proxies to `127.0.0.1:8001`.

No SSH access from CI is needed, so the security group can keep SSH on "My IP".

## One-time setup

1. GitHub: after the first CI run, set the `surl` package to **Public**
   (Profile -> Packages -> surl -> Package settings). The image holds no secrets.
2. AWS: launch/resize to `t3.micro` (or `t2.micro` where that is the free-tier type).
   Security group: 22 from My IP, 80 and 443 from anywhere. **Not** 8001.
   Attach an Elastic IP and point the domain's A record at it.
3. On the instance:
   ```
   git clone -b deploy https://github.com/joeljohngeorge8080/SURL.git ~/SURL && cd ~/SURL
   cp .env.example .env && nano .env        # add VIRUSTOTAL_API_KEY, URLHAUS_API_KEY
   DOMAIN=your.domain CERT_EMAIL=you@example.com ./deploy/bootstrap.sh
   ```
   Use `SKIP_TLS=1` first if DNS is not ready, then re-run without it.
4. Check: `curl https://your.domain/health`, `journalctl -u surl-deploy -n 20`.

## Notes

- Memory: container capped at 750 MB (+ swap up to 2 GB total); `MAX_CONCURRENT_BROWSERS=1`.
- Egress firewall (`surl-egress.service`) blocks the sandbox from private/metadata ranges.
- If another project already uses port 8001, change `API_PORT` in `.env` and re-run bootstrap.
- Never commit `.env` or `*.pem` keys.
