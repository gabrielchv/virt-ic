#!/usr/bin/env python3
"""Coleta um Traço: captura simultânea em todos os Pontos de Observação.

Precisa de root, porque entra nos network namespaces dos containers com nsenter.
Os containers não são modificados de forma alguma - nenhum tcpdump é instalado
dentro deles, nenhuma capability extra é concedida. Observamos o sistema real.

Todos os tcpdump rodam sob o mesmo relógio do host, então os timestamps dos
Avistamentos são diretamente comparáveis entre Pontos de Observação.
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

PROJECT = "virt-ic"
NETWORK = "virt-ic-lab"
WEB = f"{PROJECT}-web-1"
DB = f"{PROJECT}-db-1"


def sh(cmd):
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"falhou: {' '.join(cmd)}\n{out.stderr.strip()}")
    return out.stdout.strip()


def container_pid(name):
    pid = sh(["docker", "inspect", "-f", "{{.State.Pid}}", name])
    if pid in ("", "0"):
        raise SystemExit(f"container {name} não está rodando")
    return int(pid)


def bridge_interface():
    """Nome da interface de bridge que o Docker criou no host para a rede."""
    raw = sh(["docker", "network", "inspect", NETWORK])
    net = json.loads(raw)[0]
    named = net.get("Options", {}).get("com.docker.network.bridge.name")
    if named:
        return named
    return "br-" + net["Id"][:12]


def observation_points():
    web_pid = container_pid(WEB)
    db_pid = container_pid(DB)
    bridge = bridge_interface()
    # (rótulo, pid do namespace ou None para o host, interface, filtro BPF)
    return [
        ("host-lo", None, "lo", "tcp port 8080"),
        ("host-bridge", None, bridge, "not arp and not ip6"),
        ("web-eth0", web_pid, "eth0", "not arp and not ip6"),
        ("web-lo", web_pid, "lo", "not ip6"),
        ("db-eth0", db_pid, "eth0", "not arp and not ip6"),
    ]


def start_capture(point, outdir):
    label, pid, iface, bpf = point
    target = outdir / f"{label}.pcap"
    tcpdump = [
        "tcpdump", "-i", iface, "-n", "-s", "0", "-U",
        "--immediate-mode", "-Z", "root", "-w", str(target), bpf,
    ]
    cmd = ["nsenter", "-t", str(pid), "-n", *tcpdump] if pid else tcpdump
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return {"label": label, "iface": iface, "pid_ns": pid, "bpf": bpf,
            "path": target, "proc": proc}


def run_scenario(url, repeticoes):
    for i in range(repeticoes):
        out = subprocess.run(["curl", "-s", "-S", "--max-time", "10", url],
                             capture_output=True, text=True)
        status = "ok" if out.returncode == 0 else f"erro: {out.stderr.strip()}"
        print(f"  requisição {i + 1}/{repeticoes}: {status}")
        if i + 1 < repeticoes:
            time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser(description="coleta um Traço multiponto")
    ap.add_argument("--url", default="http://127.0.0.1:8080/")
    ap.add_argument("--repeticoes", type=int, default=1)
    ap.add_argument("--saida", default="traces/ultimo")
    args = ap.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("precisa de root: sudo poc/capture.py ...")
    for binario in ("docker", "tcpdump", "nsenter", "curl"):
        if not shutil.which(binario):
            raise SystemExit(f"binário ausente no host: {binario}")

    outdir = Path(args.saida)
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)

    pontos = observation_points()
    print("Pontos de Observação:")
    for label, pid, iface, bpf in pontos:
        onde = "host" if pid is None else f"netns pid {pid}"
        print(f"  {label:14s} {onde:16s} iface={iface:10s} filtro='{bpf}'")

    capturas = [start_capture(p, outdir) for p in pontos]
    time.sleep(1.5)  # deixa o tcpdump abrir os sockets antes do cenário rodar

    print(f"\nExecutando cenário contra {args.url}")
    run_scenario(args.url, args.repeticoes)

    time.sleep(1.5)  # deixa os últimos pacotes serem gravados
    for c in capturas:
        c["proc"].send_signal(signal.SIGINT)
    for c in capturas:
        try:
            c["proc"].wait(timeout=10)
        except subprocess.TimeoutExpired:
            c["proc"].kill()

    manifesto = {
        "cenario": {"url": args.url, "repeticoes": args.repeticoes},
        "pontos": [
            {"label": c["label"], "iface": c["iface"],
             "namespace": "host" if c["pid_ns"] is None else f"pid:{c['pid_ns']}",
             "arquivo": c["path"].name}
            for c in capturas
        ],
    }
    (outdir / "manifesto.json").write_text(
        json.dumps(manifesto, indent=2, ensure_ascii=False))

    print("\nTraço coletado:")
    for c in capturas:
        tamanho = c["path"].stat().st_size if c["path"].exists() else 0
        erro = c["proc"].stderr.read().decode(errors="replace").strip()
        pacotes = ""
        for linha in erro.splitlines():
            if "packets captured" in linha:
                pacotes = linha.strip()
        print(f"  {c['label']:14s} {tamanho:8d} bytes  {pacotes}")

    dono = os.environ.get("SUDO_UID")
    if dono:
        for caminho in [outdir, *outdir.iterdir()]:
            os.chown(caminho, int(dono), int(os.environ.get("SUDO_GID", dono)))

    print(f"\nTraço em {outdir}/")


if __name__ == "__main__":
    main()
