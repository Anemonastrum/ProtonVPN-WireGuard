import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

import yaml

from generate_openclash import endpoint, generate, make_proxy


KEY = base64.b64encode(bytes(range(32))).decode()
CONF = f"""[Interface]
PrivateKey = {KEY}
Address = 10.2.0.2/32, 2a07:b944::2:2/128
DNS = 10.2.0.1, 2a07:b944::2:1, example.lan
MTU = 1380

[Peer]
PublicKey = {KEY}
PresharedKey = {KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.5:51820
PersistentKeepalive = 25
"""


class ConverterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, entries):
        path = self.root / "configs.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in entries:
                archive.writestr(name, content)
        return path

    def test_wireguard_fields_and_ipv4_dns(self):
        proxy = make_proxy("US/test.conf", CONF)
        self.assertEqual(proxy["private-key"], KEY)
        self.assertEqual(proxy["public-key"], KEY)
        self.assertEqual(proxy["pre-shared-key"], KEY)
        self.assertEqual(proxy["ip"], "10.2.0.2")
        self.assertEqual(proxy["ipv6"], "2a07:b944::2:2")
        self.assertEqual(proxy["allowed-ips"], ["0.0.0.0/0", "::/0"])
        self.assertEqual(proxy["dns"], ["10.2.0.1"])
        self.assertEqual(proxy["mtu"], 1380)
        self.assertEqual(proxy["persistent-keepalive"], 25)

    def test_ipv6_endpoint_and_dns(self):
        content = CONF.replace("203.0.113.5:51820", "[2001:db8::1]:51820")
        proxy = make_proxy("JP/test.conf", content, ipv6=True)
        self.assertEqual(proxy["server"], "2001:db8::1")
        self.assertEqual(proxy["port"], 51820)
        self.assertEqual(proxy["dns"], ["10.2.0.1", "2a07:b944::2:1"])

    def test_country_groups_include_every_proxy_once(self):
        path = self.archive([("US/same.conf", CONF), ("JP/same.conf", CONF), ("US/other.conf", CONF)])
        config, summary = generate(path)
        self.assertEqual(summary["countries"], {"JP": 1, "US": 2})
        self.assertEqual(summary["total_configs"], 3)
        groups = {g["name"]: g for g in config["proxy-groups"]}
        names = {p["name"] for p in config["proxies"]}
        self.assertEqual(len(names), 3)
        self.assertEqual(set(groups["All Countries Load Balance"]["proxies"]), names)
        members = groups["US Load Balance"]["proxies"] + groups["JP Load Balance"]["proxies"]
        self.assertCountEqual(members, names)
        self.assertNotIn("DIRECT", groups["All Countries Load Balance"]["proxies"])
        self.assertEqual(config["rules"][-1], "MATCH,PROTONVPN")

    def test_filename_country_and_unknown_country(self):
        path = self.archive([("wg-sg-free-1.conf", CONF), ("custom.conf", CONF)])
        _, summary = generate(path)
        self.assertEqual(summary["countries"], {"OTHER": 1, "SG": 1})

    def test_directory_and_zip_are_equivalent_and_deterministic(self):
        entries = [("US/wg-US-2.conf", CONF), ("JP/wg-JP-1.conf", CONF)]
        archive = self.archive(entries)
        folder = self.root / "configs"
        for name, content in entries:
            file = folder / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content)
        self.assertEqual(generate(archive), generate(folder))
        self.assertEqual(generate(archive), generate(archive))

    def test_strategy_and_ipv6_options(self):
        archive = self.archive([("CH/server.conf", CONF)])
        config, summary = generate(archive, "round-robin", ipv6=True)
        self.assertTrue(config["ipv6"])
        self.assertTrue(config["dns"]["ipv6"])
        self.assertEqual(summary["strategy"], "round-robin")
        for group in config["proxy-groups"]:
            if group["type"] == "load-balance":
                self.assertEqual(group["strategy"], "round-robin")

    def test_multiple_peers_preserve_fields(self):
        content = CONF.replace("0.0.0.0/0, ::/0", "10.3.0.0/16")
        content += f"\n[Peer]\nPublicKey = {KEY}\nAllowedIPs = 10.4.0.0/16\nEndpoint = vpn.example:51821\nPersistentKeepalive = 25\n"
        proxy = make_proxy("NL/test.conf", content)
        self.assertNotIn("server", proxy)
        self.assertEqual(len(proxy["peers"]), 2)
        self.assertEqual(proxy["peers"][1]["server"], "vpn.example")
        self.assertEqual(proxy["peers"][1]["allowed-ips"], ["10.4.0.0/16"])

    def test_empty_or_invalid_configs_fail_instead_of_skipping(self):
        with self.assertRaisesRegex(ValueError, "No .conf"):
            generate(self.archive([("README.txt", "empty")]))
        with self.assertRaisesRegex(ValueError, "Missing required field"):
            generate(self.archive([("US/good.conf", CONF), ("JP/bad.conf", CONF.replace(f"PublicKey = {KEY}\n", ""))]))

    def test_unsafe_archive_paths_and_duplicate_names_fail(self):
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            generate(self.archive([("../wg-US-1.conf", CONF)]))
        # Different case in a file extension must not hide a name collision.
        with self.assertRaisesRegex(ValueError, "Duplicate proxy name"):
            generate(self.archive([("US/test.conf", CONF), ("US/test.CONF", CONF)]))

    def test_invalid_keys_and_numeric_values_do_not_echo_credentials(self):
        sensitive = "THIS-IS-A-PRIVATE-KEY"
        with self.assertRaises(ValueError) as caught:
            make_proxy("US/test.conf", CONF.replace(f"PrivateKey = {KEY}", f"PrivateKey = {sensitive}"))
        self.assertNotIn(sensitive, str(caught.exception))
        for content in (CONF.replace("MTU = 1380", "MTU = invalid"),
                        CONF.replace("PersistentKeepalive = 25", "PersistentKeepalive = -1")):
            with self.assertRaises(ValueError):
                make_proxy("US/test.conf", content)

    def test_endpoint_validation(self):
        for value in ("host", "host:0", "host:65536", "2001:db8::1:123", "[127.0.0.1]:123"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                endpoint(value)

    def test_cli_writes_yaml_and_summary_and_failure_writes_nothing(self):
        script = str(Path(__file__).resolve().parents[1] / "generate_openclash.py")
        archive = self.archive([("US/server.conf", CONF)])
        output, summary = self.root / "dist/config.yaml", self.root / "dist/summary.json"
        result = subprocess.run([sys.executable, script, "--input", str(archive), "--output", str(output),
                                 "--summary", str(summary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(yaml.safe_load(output.read_text())["proxies"]), 1)
        self.assertEqual(json.loads(summary.read_text())["total_configs"], 1)
        self.assertNotIn(KEY, result.stdout + result.stderr + summary.read_text())
        output.unlink()
        self.archive([("bad.conf", "[Interface]\nPrivateKey = secret\n")])
        result = subprocess.run([sys.executable, script, "--input", str(archive), "--output", str(output)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.assertNotIn("secret", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
