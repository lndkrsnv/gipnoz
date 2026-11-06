<p align="center">
  <img src="logo.png" alt="gipnoz" width="400">
</p>

<p align="center">
  <a href="https://github.com/lndkrsnv/gipnoz/actions/workflows/ci.yml"><img src="https://github.com/lndkrsnv/gipnoz/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/lndkrsnv/gipnoz/actions/workflows/codeql.yml"><img src="https://github.com/lndkrsnv/gipnoz/actions/workflows/codeql.yml/badge.svg" alt="codeql"></a>
  <a href="https://github.com/lndkrsnv/gipnoz/releases"><img src="https://img.shields.io/github/v/release/lndkrsnv/gipnoz?include_prereleases" alt="release"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/lndkrsnv/gipnoz" alt="go version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/lndkrsnv/gipnoz" alt="license"></a>
  <a href="https://github.com/lndkrsnv/gipnoz/pkgs/container/gipnoz"><img src="https://img.shields.io/badge/ghcr.io-lndkrsnv%2Fgipnoz-blue?logo=docker&logoColor=white" alt="ghcr"></a>
</p>

Yet another tool for using the internet freely. A tunnel that looks like
regular HTTPS traffic.

## Features

- **Camouflage** — gRPC over TLS 1.3, Chrome/Firefox fingerprint, random packet
  padding, the server responds like a normal website.
- **SOCKS5 proxy on the client** — works with browsers, curl, proxychains.
- **Client-side routing** — proxy-except-direct / direct-except-proxy modes,
  rules by domains and GeoIP subnets, ready-made
  [runetfreedom](https://github.com/runetfreedom/russia-blocked-geoip) lists
  supported out of the box.
- **DoH** — optional resolver against DNS leaks.
- **One key = one device** — sharing protection.


## Server setup

Download `gipnoz-server-<version>.zip` from [Releases](https://github.com/lndkrsnv/gipnoz/releases), unpack it, then:

```bash
cd server
mv server.example.yaml server.yaml
docker compose run --rm gipnoz keygen # generate the host key, put it in server.yaml
# set DOMAIN in docker-compose.yaml and add your client public keys to server.yaml
docker compose up -d
```

Caddy terminates TLS on 443 (automatic Let's Encrypt for your domain), proxies
gRPC to gipnoz-server, and serves the static site from `server/site/`
for everything else — replace it with any content you like.

## Client setup

Download the binary for your platform from
[Releases](https://github.com/lndkrsnv/gipnoz/releases)

```bash
# Generate the client key (add the public part to auth.clients on the server):
gipnoz-client keygen
```

Config (full example — `configs/client.example.yaml`):

```yaml
server:
  address: "your-domain.com:443"
  sni: "your-domain.com"

auth:
  private_key: "<private key from keygen>"
  server_public_key: "<server public host key>"

listen:
  socks5: "127.0.0.1:1080"
```

```bash
gipnoz-client -config client.yaml
```

Verify the connection:

```bash
gipnoz-client -config client.yaml test
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

## Routing

The client can send some traffic directly and the rest through the tunnel.
Rules are plain text files — one domain or CIDR per line. The raw text lists
from the runetfreedom projects are supported as-is:
[russia-blocked-geosite](https://github.com/runetfreedom/russia-blocked-geosite)
[russia-blocked-geoip](https://github.com/runetfreedom/russia-blocked-geoip)

Evaluation order: proxy rules → direct rules → mode default.
With `geoip_lists` configured, domain targets are resolved to check their IPs —
enable `dns.doh` so those lookups don't bypass the tunnel.
