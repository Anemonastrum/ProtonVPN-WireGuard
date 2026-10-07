#!/usr/bin/env python3
"""Convert a WireGuard ZIP or directory to a complete Mihomo configuration."""

import argparse
import base64
from collections import defaultdict
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import sys
import zipfile

import yaml


STRATEGIES = ("consistent-hashing", "round-robin", "sticky-sessions")


def read_configs(source):
    source = Path(source)
    if source.is_dir():
        entries = [(p.relative_to(source).as_posix(), p.read_text(encoding="utf-8-sig"))
                   for p in sorted(source.rglob("*.conf"))]
    else:
        with zipfile.ZipFile(source) as archive:
            entries = []
            for entry in sorted(archive.infolist(), key=lambda e: e.filename):
                if entry.is_dir() or not entry.filename.lower().endswith(".conf"):
                    continue
                path = PurePosixPath(entry.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in entry.filename:
                    raise ValueError("Unsafe configuration path in archive")
                entries.append((entry.filename, archive.read(entry).decode("utf-8-sig")))
    if not entries:
        raise ValueError("No .conf files found in input")
    return entries


def split_list(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_sections(content):
    interface, peers, current = {}, [], None
    for line in content.splitlines():
        line = re.split(r"[#;]", line, maxsplit=1)[0].strip()
        if not line:
            continue
        if line == "[Interface]":
            if current is not None:
                raise ValueError("Unexpected Interface section")
            current = interface
        elif line == "[Peer]":
            current = {}
            peers.append(current)
        elif line.startswith("["):
            raise ValueError("Unsupported section")
        elif current is None or "=" not in line:
            raise ValueError("Invalid WireGuard configuration line")
        else:
            key, value = (part.strip() for part in line.split("=", 1))
            if key in current:
                raise ValueError(f"Duplicate field: {key}")
            current[key] = value
    if not interface or not peers:
        raise ValueError("Interface and Peer sections are required")
    return interface, peers


def valid_key(value, label):
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError(f"Invalid {label}; expected a base64-encoded 32-byte key") from None
    return value


def endpoint(value):
    match = re.fullmatch(r"\[([^\]]+)\]:(\d+)|([^:\s]+):(\d+)", value)
    if not match:
        raise ValueError("Invalid Endpoint; expected host:port or [IPv6]:port")
    host = match.group(1) or match.group(3)
    port = int(match.group(2) or match.group(4))
    if not 1 <= port <= 65535:
        raise ValueError("Endpoint port is out of range")
    if match.group(1):
        if ipaddress.ip_address(host).version != 6:
            raise ValueError("Bracketed endpoint must be IPv6")
    return host, port


def country_for(filename):
    path = PurePosixPath(filename)
    # The downloader stores country codes in the immediate parent folder.
    if re.fullmatch(r"[A-Za-z]{2}", path.parent.name):
        return path.parent.name.upper()
    match = re.match(r"(?:wg-)?([a-z]{2})(?:[-#_]|$)", path.stem, re.I)
    return match.group(1).upper() if match else "OTHER"


def make_proxy(filename, content, ipv6=False):
    interface, peers = parse_sections(content)
    try:
        addresses = [ipaddress.ip_interface(v).ip for v in split_list(interface["Address"])]
        proxy = {
            "name": "WG " + PurePosixPath(filename).with_suffix("").as_posix(),
            "type": "wireguard",
            "private-key": valid_key(interface["PrivateKey"], "PrivateKey"),
            "udp": True,
        }
        for version, field in ((4, "ip"), (6, "ipv6")):
            address = next((str(a) for a in addresses if a.version == version), None)
            if address:
                proxy[field] = address
        if "ip" not in proxy and (not ipv6 or "ipv6" not in proxy):
            raise ValueError("No address usable with the selected IP mode")
        converted_peers = []
        for peer in peers:
            host, port = endpoint(peer["Endpoint"])
            networks = [str(ipaddress.ip_network(v, strict=False))
                        for v in split_list(peer["AllowedIPs"])]
            if not networks:
                raise ValueError("AllowedIPs must not be empty")
            converted = {"server": host, "port": port,
                         "public-key": valid_key(peer["PublicKey"], "PublicKey"),
                         "allowed-ips": networks}
            if peer.get("PresharedKey"):
                converted["pre-shared-key"] = valid_key(peer["PresharedKey"], "PresharedKey")
            converted_peers.append(converted)
        if len(converted_peers) == 1:
            proxy.update(converted_peers[0])
        else:
            proxy["peers"] = converted_peers
        keepalives = {int(p.get("PersistentKeepalive", "0")) for p in peers}
        if len(keepalives) != 1 or any(k < 0 or k > 65535 for k in keepalives):
            raise ValueError("Peers must use the same valid PersistentKeepalive")
        proxy["persistent-keepalive"] = keepalives.pop()
        mtu = int(interface.get("MTU", "1420"))
        if not 576 <= mtu <= 9000:
            raise ValueError("MTU is out of range")
        proxy["mtu"] = mtu
        dns = []
        for value in split_list(interface.get("DNS", "")):
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                continue  # wg-quick also permits DNS search domains.
            if ipv6 or addr.version == 4:
                dns.append(str(addr))
        if dns:
            proxy.update({"remote-dns-resolve": True, "dns": dns})
        return proxy
    except KeyError as exc:
        raise ValueError(f"Missing required field: {exc.args[0]}") from None
    except ValueError as exc:
        # Never include the source text or credential values in errors.
        if str(exc).startswith(("Missing ", "Invalid ", "No ", "Peers ", "MTU ", "AllowedIPs", "Endpoint ", "Bracketed ")):
            raise
        raise ValueError("Invalid address, IP range, or numeric field") from None


def generate(source, strategy="consistent-hashing", ipv6=False):
    if strategy not in STRATEGIES:
        raise ValueError("Unsupported load-balance strategy")
    proxies, countries, names = [], defaultdict(list), set()
    for filename, content in read_configs(source):
        try:
            proxy = make_proxy(filename, content, ipv6)
        except ValueError as exc:
            raise ValueError(f"{filename}: {exc}") from None
        if proxy["name"] in names:
            raise ValueError(f"Duplicate proxy name: {proxy['name']}")
        names.add(proxy["name"])
        proxies.append(proxy)
        countries[country_for(filename)].append(proxy["name"])

    def balance(name, members):
        return {"name": name, "type": "load-balance", "strategy": strategy,
                "proxies": members, "url": "https://www.gstatic.com/generate_204",
                "interval": 300, "lazy": True}

    country_groups = [balance(f"{code} Load Balance", countries[code]) for code in sorted(countries)]
    groups = [{"name": "PROTONVPN", "type": "select",
               "proxies": [g["name"] for g in country_groups] + ["All Countries Load Balance", "Manual", "DIRECT"]},
              balance("All Countries Load Balance", [p["name"] for p in proxies]),
              *country_groups,
              {"name": "Manual", "type": "select", "proxies": [p["name"] for p in proxies]}]
    rules = [f"IP-CIDR,{network},DIRECT,no-resolve" for network in
             ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4")]
    rules += [f"IP-CIDR6,{network},DIRECT,no-resolve" for network in ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]
    rules.append("MATCH,PROTONVPN")
    config = {
        "mixed-port": 7890, "redir-port": 7892, "tproxy-port": 7893,
        "allow-lan": True, "bind-address": "*", "mode": "rule", "log-level": "info",
        "ipv6": ipv6, "external-controller": "127.0.0.1:9090",
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": ipv6,
                "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                "fake-ip-filter": ["*.lan", "*.local", "localhost"],
                "respect-rules": True,
                "default-nameserver": ["1.1.1.1", "8.8.8.8"],
                "proxy-server-nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
                "nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]},
        "proxies": proxies, "proxy-groups": groups, "rules": rules,
    }
    summary = {"total_configs": len(proxies),
               "countries": {code: len(countries[code]) for code in sorted(countries)},
               "strategy": strategy, "ipv6": ipv6}
    return config, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="ProtonVPN_WireGuard_Configs.zip")
    parser.add_argument("--output", default="config.yaml")
    parser.add_argument("--summary", help="Optional JSON summary (contains no keys)")
    parser.add_argument("--strategy", choices=STRATEGIES, default=STRATEGIES[0])
    parser.add_argument("--ipv6", action="store_true", help="Enable IPv6 DNS answers and routing")
    args = parser.parse_args()
    try:
        config, summary = generate(args.input, args.strategy, args.ipv6)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("# Generated by generate_openclash.py. Requires Mihomo/Clash Meta.\n" +
                          yaml.safe_dump(config, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
        if args.summary:
            target = Path(args.summary)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"Generated {output}: {summary['total_configs']} proxies in {len(summary['countries'])} countries")
    except (ValueError, OSError, zipfile.BadZipFile, UnicodeError):
        # OSError and malformed input exceptions may embed source values.
        print("Generation failed. Check the input path and WireGuard fields; no output was published.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
