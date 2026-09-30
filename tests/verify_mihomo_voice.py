#!/usr/bin/env python3
"""Validate generated YAML and test Voice conjunctions with an offline Mihomo.

The helper image must contain Python 3. The Mihomo executable and generated
voice.yaml/nested.yaml are supplied separately; no production config is used.
"""
import argparse
import json
import pathlib
import re
import subprocess
import time
import uuid


def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


CLIENT = """
import socket,struct,sys,time
protocol,ip,port=sys.argv[1],sys.argv[2],int(sys.argv[3])
s=socket.create_connection(('127.0.0.1',7890),timeout=2)
s.settimeout(2)
s.sendall(bytes([5,1,0]))
assert s.recv(2)==bytes([5,0])
command=1 if protocol=='TCP' else 3
address=ip if protocol=='TCP' else '0.0.0.0'
destination_port=port if protocol=='TCP' else 0
s.sendall(bytes([5,command,0,1])+socket.inet_aton(address)+struct.pack('!H',destination_port))
try:
 reply=s.recv(256)
 if protocol=='UDP':
  assert reply[1]==0 and reply[3]==1,reply
  host=socket.inet_ntoa(reply[4:8])
  udpport=struct.unpack('!H',reply[8:10])[0]
  if host=='0.0.0.0': host='127.0.0.1'
  u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  packet=bytes([0,0,0,1])+socket.inet_aton(ip)+struct.pack('!H',port)+b'synthetic-test'
  u.sendto(packet,(host,udpport))
  time.sleep(0.15)
  u.close()
except socket.timeout:
 pass
s.close()
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helper_image")
    parser.add_argument("mihomo", type=pathlib.Path)
    parser.add_argument("config_dir", type=pathlib.Path)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    mounts = ["-v", str(args.mihomo.resolve()) + ":/test/mihomo:ro",
              "-v", str(args.config_dir.resolve()) + ":/test/config:ro"]
    common = ["--platform=linux/amd64", "--network=none", "--read-only", "--cap-drop=ALL",
              "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,size=32m", *mounts]
    version = docker("run", "--rm", *common, "--entrypoint=/test/mihomo", args.helper_image, "-v")
    (args.output_dir / "version.txt").write_text(version.stdout + version.stderr)
    for filename in ["voice.yaml", "nested.yaml"]:
        result = docker("run", "--rm", *common, "--entrypoint=/test/mihomo", args.helper_image,
                        "-t", "-d", "/tmp", "-f", "/test/config/" + filename)
        (args.output_dir / (filename + ".validation.log")).write_text(result.stdout + result.stderr)
        print("PASS Mihomo configuration validation:", filename)

    voice = (args.config_dir / "voice.yaml").read_text()
    ips = sorted(set(re.findall(r"IP-CIDR,([0-9.]+)/32\)\),AI", voice)))
    assert len(ips) == 23, ips
    cases = [(protocol, ip, port, "AI[REJECT]") for ip in ips
             for protocol, port in [("UDP", 3478), ("TCP", 443)]]
    cases += [("TCP", ips[0], 3478, "Final[DIRECT]"),
              ("UDP", ips[0], 443, "Final[DIRECT]"),
              ("TCP", "203.0.113.9", 443, "Final[DIRECT]"),
              ("UDP", "203.0.113.9", 3478, "Final[DIRECT]")]
    name = "mihomo-voice-test-" + uuid.uuid4().hex[:12]
    records = []
    try:
        docker("run", "-d", "--rm", "--name", name, *common,
               "--entrypoint=/test/mihomo", args.helper_image,
               "-d", "/tmp", "-f", "/test/config/voice.yaml")
        for _ in range(60):
            probe = docker("exec", name, "python3", "-c",
                           "import socket; socket.create_connection(('127.0.0.1',7890),timeout=.2).close()",
                           check=False)
            if probe.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Offline Mihomo listener failed to start")

        for protocol, ip, port, expected in cases:
            docker("exec", name, "python3", "-c", CLIENT, protocol, ip, str(port))
            logs = docker("logs", name)
            logtext = logs.stdout + logs.stderr
            destination_logs = [line for line in logtext.splitlines()
                                if "[" + protocol + "]" in line and ip + ":" + str(port) in line]
            matched = [line for line in destination_logs if "using " + expected in line
                       or (expected == "Final[DIRECT]" and "dial Final (match Match/)" in line)]
            assert matched, (protocol, ip, port, expected, logtext[-2000:])
            if expected == "Final[DIRECT]":
                assert not any("AI[" in line or "dial AI " in line for line in destination_logs)
            records.append(dict(protocol=protocol, ip=ip, port=port, expected=expected, passed=True))
        print("PASS engine matching: 46 positive protocol/port/IP conjunction cases and 4 negative controls")
        (args.output_dir / "match-results.json").write_text(json.dumps(records, indent=2) + "\n")
        logs = docker("logs", name)
        (args.output_dir / "runtime.log").write_text(logs.stdout + logs.stderr)
    finally:
        logs = docker("logs", name, check=False)
        (args.output_dir / "runtime.log").write_text(logs.stdout + logs.stderr)
        docker("rm", "-f", name, check=False)
    print("PASS offline Mihomo container removed")


if __name__ == "__main__":
    main()
