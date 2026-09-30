#!/usr/bin/env python3
"""Exercise /sub with synthetic files in a disposable, offline Docker container.

Usage: python3 tests/verify_clash_logical_rules.py IMAGE --output-dir PATH
The saved voice.yaml can then be checked by Mihomo. No host port is published.
"""
import argparse
import pathlib
import subprocess
import tempfile
import time
import urllib.parse
import uuid


def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def rules(output):
    lines = output.splitlines()
    start = max(i for i, line in enumerate(lines) if line in ("rules:", "Rule:"))
    return [line.strip()[2:] for line in lines[start + 1:] if line.strip().startswith("- ")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    voice = [line for line in (pathlib.Path(__file__).parent / "fixtures/Voice.list").read_text().splitlines()
             if line and not line.startswith("#")]
    assert len(voice) == 46
    baseline = ["DOMAIN,baseline.example.test", "DOMAIN-SUFFIX,example.test",
                "IP-CIDR,198.51.100.0/24,no-resolve", "SRC-IP-CIDR,192.0.2.1/32",
                "DST-PORT,12345"]
    expected_baseline = ["DOMAIN,baseline.example.test,AI", "DOMAIN-SUFFIX,example.test,AI",
                         "IP-CIDR,198.51.100.0/24,AI,no-resolve", "SRC-IP-CIDR,192.0.2.1/32,AI",
                         "DST-PORT,12345,AI"]
    name = "subconverter-logical-test-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="subconverter-logical-") as directory:
        p = pathlib.Path(directory)
        (p / "pref.ini").write_text("[common]\napi_mode=false\nbase_path=codex-test\n"
                                   "clash_rule_base=codex-test/base.yaml\n"
                                   "surge_rule_base=codex-test/base.ini\n"
                                   "loon_rule_base=codex-test/base.ini\n"
                                   "quanx_rule_base=codex-test/base.ini\n"
                                   "[server]\nlisten=127.0.0.1\nport=25500\n"
                                   "[advanced]\nenable_cache=false\n")
        (p / "base.yaml").write_text("mixed-port: 7890\nmode: rule\nlog-level: debug\n"
                                    "rules:\n  - SRC-IP-CIDR,192.0.2.189/32,DIRECT\n")
        (p / "base.ini").write_text("[General]\n[Proxy]\n[Proxy Group]\n[Rule]\n")
        (p / "proxy.yaml").write_text("proxies:\n  - name: Synthetic\n    type: ss\n"
                                     "    server: 127.0.0.1\n    port: 8388\n"
                                     "    cipher: aes-128-gcm\n    password: synthetic-only\n")
        (p / "Baseline.list").write_text("\n".join(baseline) + "\n")
        (p / "Voice.list").write_text("\n".join(voice) + "\n")

        def config(name, listname="Voice.list", inline=None):
            text = ("[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\n"
                    "clash_rule_base=codex-test/base.yaml\n"
                    "ruleset=AI,codex-test/Baseline.list\n")
            if listname:
                text += "ruleset=AI,codex-test/" + listname + "\n"
            if inline:
                text += "ruleset=AI,[]" + inline + "\n"
            text += ("ruleset=Final,[]FINAL\ncustom_proxy_group=AI`select`[]REJECT\n"
                     "custom_proxy_group=Final`select`[]DIRECT\n")
            (p / name).write_text(text)

        config("voice.ini")
        try:
            docker("run", "-d", "--rm", "--pull=never", "--name", name,
                   "--network=none", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,size=32m",
                   "-v", str(p) + ":/base/codex-test:ro",
                   "-v", str(p / "pref.ini") + ":/base/pref.ini:ro", args.image)
            for _ in range(60):
                ready = docker("exec", name, "wget", "-qO-", "http://127.0.0.1:25500/version", check=False)
                if ready.returncode == 0:
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("Synthetic converter failed to start: " + docker("logs", name).stderr)

            def request(config_name="voice.ini", **extra):
                query = dict(target="clash", new_name="true", url="codex-test/proxy.yaml",
                             config="codex-test/" + config_name)
                query.update(extra)
                return docker("exec", name, "wget", "-qO-",
                              "http://127.0.0.1:25500/sub?" + urllib.parse.urlencode(query)).stdout

            output = request()
            expected = expected_baseline + [line + ",AI" for line in voice] + ["MATCH,Final"]
            assert rules(output) == expected, rules(output)
            (args.output_dir / "voice.yaml").write_text(output)
            print("PASS independent Voice.list: all 46 conjunctions, AI attachment, order, ordinary rules")

            for options in [dict(new_name="false"), dict(target="clashr")]:
                actual = rules(request(**options))
                assert actual == expected, (options, actual)
            print("PASS legacy Clash fields and ClashR")

            tailnet = rules(request(tailnet="1"))
            assert tailnet == ["SRC-IP-CIDR,192.0.2.189/32,DIRECT"] + expected
            print("PASS existing Tailnet source exception remains first")

            nested = "AND,((NETWORK,udp),(OR,((DST-PORT,3478),(DST-PORT,443))),(NOT,((DOMAIN,excluded.example.test))))"
            (p / "Nested.list").write_text(nested + "\n" + voice[0] + ",OldPolicy\n")
            config("nested.ini", "Nested.list")
            nested_output = request("nested.ini")
            assert rules(nested_output) == expected_baseline + [nested + ",AI", voice[0] + ",AI", "MATCH,Final"]
            (args.output_dir / "nested.yaml").write_text(nested_output)
            config("inline.ini", None, nested)
            assert rules(request("inline.ini")) == expected_baseline + [nested + ",AI", "MATCH,Final"]
            print("PASS nested AND/OR/NOT, explicit policy replacement and inline path")

            malformed = [voice[0][:-1], voice[0] + ",", voice[0] + ",Old,Extra",
                         "AND,((NETWORK,udp),)", "AND,((NETWORK,udp))",
                         "NOT,((NETWORK,udp),(DST-PORT,3478))", "AND,((NETWORK,),(DST-PORT,3478))",
                         "ANDROMEDA,example.test"]
            (p / "Invalid.list").write_text("\n".join(malformed) + "\n")
            config("invalid.ini", "Invalid.list")
            assert rules(request("invalid.ini")) == expected_baseline + ["MATCH,Final"]
            config("invalid-inline.ini", None, malformed[0])
            assert rules(request("invalid-inline.ini")) == expected_baseline + ["MATCH,Final"]
            assert rules(request()) == expected
            print("PASS malformed logical rules are omitted with warnings; subsequent conversion works")

            config("ordinary.ini", None)
            for target in ["surge", "loon", "quanx"]:
                other = request("ordinary.ini", target=target, ver="4")
                ordinary = [line for line in other.splitlines() if line.startswith(
                    ("DOMAIN,", "DOMAIN-SUFFIX,", "IP-CIDR,", "SRC-IP-CIDR,", "FINAL,"))]
                assert ordinary == expected_baseline[:-1] + ["FINAL,Final"], other
                (args.output_dir / (target + ".txt")).write_text(other)
            print("PASS ordinary rule conversion for Surge 4, Loon and Quantumult X")
            logs = docker("logs", name)
            logtext = logs.stdout + logs.stderr
            assert "Ignoring malformed Clash logical rule" in logtext
            (args.output_dir / "converter.log").write_text(logtext)
        finally:
            docker("rm", "-f", name, check=False)
    print("PASS disposable container removed; outputs:", args.output_dir)


if __name__ == "__main__":
    main()
