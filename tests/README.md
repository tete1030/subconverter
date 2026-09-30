# Clash logical rules

The `/sub` Clash and ClashR ruleset generators preserve `AND`, `OR` and `NOT`
expressions, including nested commas, and attach the policy from `ruleset=`.
An existing policy after the expression is replaced. Ordinary rule conversion
and the separate Surge/Quantumult/Loon and `/getruleset` paths retain their
existing behavior. This deliberately avoids changing the shared type whitelist
used by other converters that still split on individual commas.

Logical input must contain balanced parenthesized conditions; `AND` and `OR`
require at least two conditions, and `NOT` requires one. Malformed logical rules
are omitted with a warning rather than emitted as truncated or broader rules.
Final configuration validation remains the responsibility of the target engine.

The approach was reviewed against RichardLuo0's upstream
[PR #823](https://github.com/tindy2013/subconverter/pull/823). Its general
comma-count shortcut is not used here. The existing GPL-3.0 license is retained.

Build a disposable image from the repository root:

```sh
docker buildx build --platform linux/amd64 -f scripts/Dockerfile \
  --build-arg SHA=logical-test -t subconverter:logical-test --load .
python3 tests/verify_clash_logical_rules.py subconverter:logical-test \
  --output-dir /tmp/subconverter-logical-output
```

The suite uses synthetic local subscriptions, publishes no host port, and runs
the converter with no network, a read-only root filesystem and no capabilities.
It checks all 46 rules in the reviewed Voice.list fixture, policy attachment,
nesting, inline input, malformed input, legacy fields, Tailnet rule preservation,
and ordinary rule output for Clash, ClashR, Surge 4, Loon and Quantumult X.

To validate syntax and actual TCP/UDP matching, supply a Linux amd64 Mihomo
executable and a Linux amd64 helper image containing Python 3:

```sh
python3 tests/verify_mihomo_voice.py HELPER_IMAGE /path/to/mihomo \
  /tmp/subconverter-logical-output --output-dir /tmp/mihomo-logical-output
```

That suite runs Mihomo without network or published ports, checks generated YAML,
tests every fixture address with UDP/3478 and TCP/443, and verifies that protocol,
port and IP negative controls reach the fallback policy. Both suites remove their
own containers and save only synthetic configurations and test logs.
