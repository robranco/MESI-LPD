#!/usr/bin/env python3
import argparse
import getpass
import ipaddress
import shlex
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Set, Tuple


class Ansi:
    reset = "\033[0m"
    yellow = "\033[33m"
    green = "\033[32m"
    red = "\033[31m"

    @staticmethod
    def maybe_disable(enabled: bool) -> None:
        if not enabled:
            for attr in ("reset", "yellow", "green", "red"):
                setattr(Ansi, attr, "")


def positive_int(value: str) -> int:
    linhas = int(value)
    if linhas <= 0:
        raise argparse.ArgumentTypeError("o número de linhas deve ser um inteiro positivo")
    return linhas


IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def resolve_host_ips(host: str) -> Tuple[Set[str], Set[IpAddress]]:
    """Resolve o host para endereços IP e apelidos comuns."""

    aliases: set[str] = set()
    addr_objects: set[IpAddress] = set()
    errors: list[str] = []

    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            records = socket.getaddrinfo(host, None, family=family)
        except socket.gaierror as exc:
            errors.append(str(exc))
            continue

        for info in records:
            sockaddr = info[4]
            if not sockaddr:
                continue
            ip = sockaddr[0]
            if isinstance(ip, (bytes, bytearray)):
                ip = ip.decode("ascii", "ignore")
            else:
                ip = str(ip)
            expanded = _expand_ip_aliases(ip)
            aliases.update(expanded)
            for candidate in expanded:
                try:
                    addr_objects.add(ipaddress.ip_address(candidate))
                except ValueError:
                    continue

    # Tentativa extra para resolvers que só retornam IPv4
    try:
        host_info = socket.gethostbyname_ex(host)
    except socket.gaierror as exc:
        errors.append(str(exc))
    else:
        for ip in host_info[2]:
            expanded = _expand_ip_aliases(ip)
            aliases.update(expanded)
            for candidate in expanded:
                try:
                    addr_objects.add(ipaddress.ip_address(candidate))
                except ValueError:
                    continue

    if not aliases and errors:
        print(
            f"{Ansi.yellow}Aviso: não foi possível resolver {host}: {', '.join(errors)}{Ansi.reset}",
            file=sys.stderr,
        )
    return aliases, addr_objects


def _expand_ip_aliases(ip: str) -> set[str]:
    aliases = {ip, ip.lower()}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return aliases

    if isinstance(addr, ipaddress.IPv4Address):
        mapped = f"::ffff:{addr.compressed}"
        aliases.update({addr.compressed, addr.exploded, mapped, mapped.lower()})
    else:
        aliases.update({addr.compressed, addr.compressed.lower(), addr.exploded.lower(), addr.exploded})

    return aliases


def should_ignore_client_ip(
    client_ip: str,
    host_aliases: Set[str],
    host_addr_objects: Set[IpAddress],
) -> bool:
    candidate = client_ip.strip()
    if not candidate:
        return False

    # Remove colchetes opcionais de endereços IPv6 como [2001:db8::1]
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
        if not candidate:
            return False

    candidate_lower = candidate.lower()
    if candidate in host_aliases or candidate_lower in host_aliases:
        return True

    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False

    if addr.is_loopback:
        return True

    if addr in host_addr_objects:
        return True

    if isinstance(addr, ipaddress.IPv4Address):
        mapped = ipaddress.IPv6Address(f"::ffff:{addr.compressed}")
        if mapped in host_addr_objects:
            return True

    return False


def run_tail(host: str, port: int, username: str, remote_file: str, line_count: int) -> int:
    print(f"{Ansi.yellow}Conectando em {username}@{host}:{port}\u2026{Ansi.reset}", file=sys.stderr)
    host_aliases, host_addr_objects = resolve_host_ips(host)
    ssh_password = getpass.getpass("Senha SSH (deixe em branco para usar chave/agente): ")

    default_answer = "yes"
    sudo_same = input(
        f"A senha do sudo é igual à senha SSH? [{default_answer}/no]: "
    ).strip().lower()

    if sudo_same in ("", "y", "yes") and ssh_password:
        sudo_password = ssh_password
    else:
        sudo_password = getpass.getpass("Senha sudo: ")

    if not sudo_password:
        print(
            f"{Ansi.red}Uma senha sudo é necessária para continuar.{Ansi.reset}",
            file=sys.stderr,
        )
        return 1

    remote_cmd = f"sudo -S -p '' tail -n {line_count} {shlex.quote(remote_file)}"
    ssh_cmd = ["ssh", "-tt", "-p", str(port), f"{username}@{host}", remote_cmd]

    proc = subprocess.Popen(
        ssh_cmd,
        stdin=subprocess.PIPE,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if proc.stdin is None:
        print(f"{Ansi.red}O processo SSH não forneceu stdin.{Ansi.reset}", file=sys.stderr)
        return 1

    # Provide SSH password if supplied (ssh itself consumes it before remote command executes)
    if ssh_password:
        try:
            proc.stdin.write(ssh_password + "\n")
            proc.stdin.flush()
        except BrokenPipeError:
            print(f"{Ansi.red}Falha ao enviar a senha SSH (broken pipe).{Ansi.reset}", file=sys.stderr)
            return 1

    try:
        proc.stdin.write(sudo_password + "\n")
        proc.stdin.flush()
    except BrokenPipeError:
        print(f"{Ansi.red}Falha ao enviar a senha sudo (broken pipe).{Ansi.reset}", file=sys.stderr)
        return 1
    finally:
        proc.stdin.close()

    # Stream stdout with simple color highlighting
    if proc.stdout is None or proc.stderr is None:
        print(f"{Ansi.red}O processo SSH não forneceu streams de saída.{Ansi.reset}", file=sys.stderr)
        return 1

    linhas_emitidas = 0
    linhas_filtradas = 0

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
    output_path = Path(f"{Path(remote_file).name}_{timestamp}.txt")

    try:
        destino = output_path.open("w", encoding="utf-8")
    except OSError as exc:
        print(
            f"{Ansi.red}Não foi possível criar o arquivo de saída {output_path}: {exc}{Ansi.reset}",
            file=sys.stderr,
        )
        destino = None

    for line in proc.stdout:
        if "DigitalOcean" in line or "mod_pagespeed" in line or "munin" in line:
            linhas_filtradas += 1
            continue

        stripped = line.rstrip()
        if not stripped:
            linhas_filtradas += 1
            continue

        parts = stripped.split()
        if not parts:
            linhas_filtradas += 1
            continue

        client_ip_field = parts[0]
        if should_ignore_client_ip(client_ip_field, host_aliases, host_addr_objects):
            linhas_filtradas += 1
            continue

        print(f"{Ansi.green}{stripped}{Ansi.reset}")
        if destino is not None:
            destino.write(stripped + "\n")
        linhas_emitidas += 1
    proc.stdout.close()

    if destino is not None:
        destino.close()

    stderr_output = proc.stderr.read()
    proc.stderr.close()
    if stderr_output:
        print(f"{Ansi.red}{stderr_output.rstrip()}{Ansi.reset}", file=sys.stderr)

    if destino is not None:
        print(
            f"{Ansi.yellow}Saída salva em {output_path}.{Ansi.reset}",
            file=sys.stderr,
        )

    if linhas_emitidas < line_count:
        faltando = line_count - linhas_emitidas
        print(
            f"{Ansi.yellow}Aviso: {faltando} linhas foram filtradas ou não estavam disponíveis.{Ansi.reset}",
            file=sys.stderr,
        )
    if linhas_filtradas:
        print(
            f"{Ansi.yellow}Linhas ignoradas pelos filtros: {linhas_filtradas}.{Ansi.reset}",
            file=sys.stderr,
        )

    return proc.wait()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Busca as últimas N linhas de um arquivo remoto via ssh e sudo tail.",
    )
    parser.add_argument("host", help="Remote host or IP address")
    parser.add_argument("username", help="SSH username")
    parser.add_argument("remote_file", help="Remote file path to read")
    parser.add_argument(
        "-n",
        "--lines",
        type=positive_int,
        default=50,
        help="Número de linhas a buscar (padrão: 50)",
    )
    parser.add_argument("-p", "--port", type=int, default=None, help="Porta SSH (padrão: 22)")
    args = parser.parse_args()

    port = args.port
    if port is None:
        port_input = input("Porta SSH [22]: ").strip()
        if port_input:
            try:
                port = int(port_input)
            except ValueError:
                print(f"{Ansi.red}Porta inválida '{port_input}'.{Ansi.reset}", file=sys.stderr)
                return 1
        else:
            port = 22

    Ansi.maybe_disable(sys.stdout.isatty())
    return run_tail(args.host, port, args.username, args.remote_file, args.lines)


if __name__ == "__main__":
    raise SystemExit(main())
