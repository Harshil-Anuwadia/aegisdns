#!/usr/bin/env python3
"""AegisDNS setup: a terminal UI over explicit, recoverable lifecycle steps."""
from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import time

ROOT = Path(__file__).resolve().parent.parent
WINDOWS = os.name == 'nt'
CLI_LINK = Path('/usr/local/bin/aegis')


class SetupError(Exception):
    pass


class UI:
    def __init__(self, plain=False):
        # The installer has an explicit --plain mode. Interactive runs use color
        # even when a parent application exports TERM=dumb or NO_COLOR globally.
        self.tty = sys.stdout.isatty() and not plain
        self.color = self.tty
        self.motion = self.tty and not os.environ.get('AEGIS_NO_ANIMATION')
        if WINDOWS and self.tty:
            try:
                import ctypes
                handle = ctypes.windll.kernel32.GetStdHandle(-11)
                mode = ctypes.c_ulong()
                if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)) or not ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 4):
                    self.tty = self.color = self.motion = False
            except Exception:
                self.tty = self.color = self.motion = False

    def ink(self, text, code='36'):
        return f'\033[{code}m{text}\033[0m' if self.color else text

    def say(self, text='', indent='  '):
        width = max(28, min(76, shutil.get_terminal_size((80, 24)).columns - 4))
        text = str(text)
        encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
        try:
            text.encode(encoding)
        except UnicodeEncodeError:
            text = text.translate(str.maketrans({'─':'-', '✓':'OK', '…':'...', '’':"'", '‘':"'", '·':'/'})).encode(encoding, errors='replace').decode(encoding)
        for line in text.splitlines() or ['']:
            for wrapped in textwrap.wrap(line, width=width, replace_whitespace=False) or ['']:
                print(indent + wrapped, flush=True)

    def welcome(self, uninstall=False):
        print()
        self.say(self.ink('AEGISDNS', '1;36'))
        self.say('Safe removal' if uninstall else 'Secure DNS for your network')
        print()

    def step(self, index, total, title):
        if index > 1:
            print()
        self.say(self.ink(f'{index:02d}', '1;36') + '  ' + self.ink(title, '1;37') + '  ' + self.ink(f'{index}/{total}', '2'))

    def done(self, message):
        self.say(self.ink('✓ ' + message, '1;32'))

    def warn(self, message):
        self.say(self.ink('!  ' + message, '1;33'))

    def confirm(self, question, yes=False, default=False, word=None):
        if yes:
            return True
        if not sys.stdin.isatty():
            raise SetupError('No interactive input. Review --help, then use --yes for an unattended run.')
        suffix = f' Type {word}: ' if word else (' [Y/n] ' if default else ' [y/N] ')
        self.say(self.ink(question, '1;37'))
        try:
            answer = input('  ' + suffix).strip()
        except EOFError:
            raise SetupError('Input closed. No further changes were made.') from None
        if word:
            return answer == word
        return answer.lower() in ('y', 'yes') or (not answer and default)


class Runner:
    def __init__(self, ui, log):
        self.ui, self.log = ui, log

    def run(self, args, *, capture=False, timeout=1800, interactive=False, check=True):
        args = [str(a) for a in args]
        if interactive:
            result = subprocess.run(args, cwd=ROOT, timeout=timeout)
            if check and result.returncode:
                raise SetupError(f'{Path(args[0]).name} did not complete successfully.')
            return ''
        started = time.monotonic()
        env = dict(os.environ, NO_COLOR='1', COMPOSE_ANSI='never', BUILDKIT_PROGRESS='plain')
        # A private scratch file avoids pipe deadlocks and keeps large build output off the UI.
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, env=env, start_new_session=not WINDOWS)
            frame = 0
            spinner = '|/-\\'
            try:
                if self.ui.motion:
                    print('\033[?25l', end='', flush=True)
                while process.poll() is None:
                    elapsed = int(time.monotonic() - started)
                    if elapsed > timeout:
                        raise SetupError(f'{Path(args[0]).name} exceeded the {timeout}s timeout.')
                    if self.ui.motion:
                        status = self.ui.ink(spinner[frame % 4], '1;36')
                        elapsed_text = self.ui.ink(f'{elapsed}s', '2')
                        print(f'\r\033[2K  {status} Working  {elapsed_text}', end='', flush=True)
                        frame += 1
                    time.sleep(.15)
                output.seek(0)
                content = output.read(16 * 1024 * 1024).decode('utf-8', errors='replace') if capture else ''
                content = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', content)
                if check and process.returncode:
                    raise SetupError(f'{Path(args[0]).name} failed (exit {process.returncode}). Details: {self.log}')
                return (content.strip() if process.returncode == 0 else '') if capture else process.returncode
            finally:
                if process.poll() is None:
                    if WINDOWS:
                        process.terminate()
                    else:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if WINDOWS:
                            process.kill()
                        else:
                            with contextlib.suppress(ProcessLookupError):
                                os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                output.seek(0)
                with self.log.open('ab') as log:
                    log.write(f'\n[{Path(args[0]).name}; exit {process.returncode}]\n'.encode())
                    shutil.copyfileobj(output, log)
                if self.ui.motion:
                    print('\r\033[2K\033[?25h', end='', flush=True)


def atomic_write(path, content, mode=0o600):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SetupError(f'Refusing to replace a symlink or non-file: {path}')
    fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare_config(root, address, backup):
    ipaddress.IPv4Address(address)
    for name in ('config.json', '.env', 'openroot.json'):
        p = root / name
        if p.is_symlink() or (p.exists() and not p.is_file()):
            raise SetupError(f'{p} must be a regular file, not a symlink or directory.')
    blocklists = root / 'blocklists'
    if blocklists.is_symlink() or (blocklists.exists() and not blocklists.is_dir()):
        raise SetupError('blocklists must be a directory, not a symlink or regular file.')
    path = root / 'config.json'
    config = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    if not isinstance(config, dict) or not isinstance(config.get('host_ips', []), list) or any(not isinstance(x, str) for x in config.get('host_ips', [])):
        raise SetupError('config.json must contain an object with a host_ips array of strings.')
    zone = root / 'openroot.json'
    zones = json.loads((zone if zone.exists() else root / 'openroot.example.json').read_text(encoding='utf-8'))
    if not isinstance(zones, dict):
        raise SetupError('openroot.json must contain a JSON object.')
    env_path = root / '.env'
    lines = env_path.read_text(encoding='utf-8').splitlines() if env_path.exists() else []
    for name in ('config.json', '.env', 'openroot.json'):
        source = root / name
        if source.exists():
            shutil.copyfile(source, backup / name)
            os.chmod(backup / name, 0o600)
    ips = config.setdefault('host_ips', [])
    for ip in ('127.0.0.1', address):
        if ip not in ips:
            ips.append(ip)
    # Never source .env as shell code. Preserve unrelated values, comments and secrets.
    lines = [line for line in lines if not re.match(r'^\s*(?:export\s+)?AEGIS_HOST_IP\s*=', line)]
    lines.append(f'AEGIS_HOST_IP={address}')
    config_mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    atomic_write(path, json.dumps(config, indent=2) + '\n', config_mode)
    atomic_write(env_path, '\n'.join(lines) + '\n')
    if not zone.exists():
        atomic_write(zone, (root / 'openroot.example.json').read_text(encoding='utf-8'), 0o644)
    blocklists = root / 'blocklists'
    if blocklists.is_symlink() or (blocklists.exists() and not blocklists.is_dir()):
        raise SetupError('blocklists must be a directory, not a symlink or regular file.')
    blocklists.mkdir(exist_ok=True)


@contextlib.contextmanager
def setup_lock(root):
    path = root / '.aegis-setup.lock'
    if path.is_symlink():
        raise SetupError('The setup lock must not be a symlink.')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        try:
            if WINDOWS:
                import msvcrt
                if not path.stat().st_size:
                    lock.write(b'0'); lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SetupError('Another installer or uninstaller is running in this checkout.') from None
        # Keep the inode in place: deleting an active lock permits concurrent writers.
        yield


def dns_check(address='127.0.0.1', port=53, tcp=False):
    # Root NS query: no per-user hostname and no need for dig or nslookup.
    transaction = int.from_bytes(os.urandom(2), 'big')
    packet = struct.pack('!HHHHHH', transaction, 0x0100, 1, 0, 0, 0) + b'\x00\x00\x02\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.connect((address, port))
        if tcp:
            def receive(length):
                data = b''
                while len(data) < length:
                    chunk = sock.recv(length-len(data))
                    if not chunk:
                        raise OSError('Truncated DNS response')
                    data += chunk
                return data
            sock.sendall(struct.pack('!H', len(packet)) + packet)
            result = receive(struct.unpack('!H', receive(2))[0])
        else:
            sock.send(packet)
            result = sock.recv(65535)
    if len(result) < 12:
        return False
    ident, flags, _, answers, _, _ = struct.unpack('!HHHHHH', result[:12])
    return ident == transaction and bool(flags & 0x8000) and not (flags & 0x020F) and answers > 0


class Setup:
    def __init__(self, args, ui, runner, backup):
        self.args, self.ui, self.runner, self.backup = args, ui, runner, backup
        self.docker = ['docker']
        self.compose = []
        self.started = False
        self.sudo_announced = False

    def sudo(self):
        if WINDOWS:
            return []
        if not shutil.which('sudo'):
            raise SetupError('sudo is required. Install sudo, then run setup as your regular user.')
        if not self.sudo_announced:
            self.ui.say('Administrator permission is required for host DNS and the aegis command.')
            self.sudo_announced = True
        command = ['sudo', '-n', 'true'] if self.args.yes else ['sudo', '-v']
        self.runner.run(command, interactive=not self.args.yes, timeout=120)
        return ['sudo', '-n'] if self.args.yes else ['sudo']

    def sudo_run(self, *command, timeout=120):
        """Run one privileged command without assuming sudo timestamp caching."""
        prefix = ['sudo', '-n'] if self.args.yes else ['sudo']
        return self.runner.run(prefix + list(command), interactive=not self.args.yes,
                               timeout=timeout)

    def requirements(self):
        if not WINDOWS and sys.platform != 'linux':
            raise SetupError('Use a Linux host for AegisDNS. This installer does not configure macOS DNS.')
        if not WINDOWS and os.geteuid() == 0:
            raise SetupError('Run setup as a regular user, not root. sudo is requested for host changes.')
        names = ['docker-compose.yml', 'aegis', 'openroot.example.json']
        if self.args.action == 'install':
            names += ['Dockerfile', 'Dockerfile.openroot', 'Cargo.lock', 'ui/package-lock.json']
        for name in names:
            if not (ROOT / name).is_file():
                raise SetupError(f'Missing {name}. Run setup from a complete AegisDNS checkout.')
        if self.args.action == 'install' and shutil.disk_usage(ROOT).free < 2 * 1024**3:
            raise SetupError('Less than 2 GiB of free disk space. Free space for the source build and Docker images, then retry.')
        if not WINDOWS and not self.args.no_start and self.args.action == 'install' and not shutil.which('curl'):
            raise SetupError('curl is required for startup checks. Install curl with your system package manager.')

    def dependency(self, name, url):
        if shutil.which(name):
            return
        if WINDOWS:
            raise SetupError(f'Install {name} first, then retry. Docker Desktop must use Linux containers with host networking enabled.')
        if self.args.action == 'uninstall':
            raise SetupError('Docker is unavailable. Restore the Docker connection to remove containers. On Linux, aegis restore-dns can recover saved host DNS separately.')
        if not self.args.install_deps:
            if self.args.yes or not self.ui.confirm(f'{name} is missing. Install it now using its official installation script?', default=True):
                raise SetupError(f'{name} is missing. Install it first, or rerun with --install-deps to use its official installation script.')
        if not shutil.which('curl'):
            raise SetupError('Install curl before using --install-deps.')
        target = self.backup / f'{name}-install.sh'
        self.runner.run(['curl', '-fL', '--proto', '=https', '--tlsv1.2', '--connect-timeout', '15', '--max-time', '120', url, '-o', target], timeout=130)
        self.sudo_run('sh', target, timeout=900)

    def connect_docker(self):
        self.dependency('docker', 'https://get.docker.com')
        result = self.runner.run(['docker', 'info', '--format', '{{.OperatingSystem}}'], capture=True, check=False, timeout=25)
        if not isinstance(result, str) or not result or 'error' in result.lower():
            if WINDOWS:
                raise SetupError('Start Docker Desktop, wait for its Linux engine, and retry.')
            self.sudo()
            self.docker = ['sudo', '-n', 'docker']
            result = self.runner.run(self.docker + ['info', '--format', '{{.OperatingSystem}}'], capture=True, check=False, timeout=25)
            if not result:
                raise SetupError('Docker Engine is not reachable. Start it (usually sudo systemctl start docker), check the Docker context, then retry.')
        endpoint = os.environ.get('DOCKER_HOST') or self.runner.run(self.docker + ['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], capture=True, timeout=20)
        if not endpoint.startswith(('unix://', 'npipe://')):
            raise SetupError('Use a local Docker Engine socket. Remote/TCP Docker contexts cannot safely configure this host’s DNS.')
        security = self.runner.run(self.docker + ['info', '--format', '{{json .SecurityOptions}}'], capture=True, timeout=20)
        if 'rootless' in security.lower():
            raise SetupError('Rootless Docker isolates host networking. Use a rootful Docker Engine for this DNS deployment.')
        if 'Docker Desktop' in result:
            self.ui.warn('Docker Desktop requires host networking enabled. NAT can hide client IPs; native Linux is recommended for device policies and DHCP.')
            if not self.args.allow_desktop and (self.args.yes or not self.ui.confirm('Continue with Docker Desktop?', default=False)):
                raise SetupError('Docker Desktop was not selected. Use native Docker Engine or --allow-desktop after enabling host networking.')
        self.runner.run(self.docker + ['compose', 'version'], timeout=25)
        self.compose = self.docker + ['compose', '--project-directory', str(ROOT), '-f', str(ROOT / 'docker-compose.yml')]
        projects = set()
        file_sets = set()
        for name in ('aegisdns', 'openroot'):
            raw = self.runner.run(self.docker + ['inspect', name], capture=True, check=False, timeout=20)
            try:
                containers = json.loads(raw)
            except (ValueError, TypeError):
                containers = []
            for container in containers if isinstance(containers, list) else []:
                labels = container.get('Config', {}).get('Labels') or {}
                directory = labels.get('com.docker.compose.project.working_dir')
                if not directory or Path(directory).resolve() != ROOT or not labels.get('com.docker.compose.project'):
                    raise SetupError(f'The container named {name} belongs to another installation. It will not be changed.')
                projects.add(labels['com.docker.compose.project'])
                files = tuple(labels.get('com.docker.compose.project.config_files', str(ROOT / 'docker-compose.yml')).split(','))
                for file in files:
                    path = Path(file).resolve()
                    if not path.is_relative_to(ROOT) or not path.is_file():
                        raise SetupError('The installed Compose files are missing or outside this checkout. Restore that configuration before setup.')
                file_sets.add(files)
        if len(projects) > 1:
            raise SetupError('The AegisDNS containers belong to different Compose projects. Resolve the conflict before setup.')
        if len(file_sets) > 1:
            raise SetupError('Installed containers use different Compose files; resolve this before setup.')
        if file_sets:
            self.compose = self.docker + ['compose', '--project-directory', str(ROOT)]
            for file in file_sets.pop():
                self.compose += ['-f', file]
        if projects:
            self.compose += ['--project-name', projects.pop()]
        self.runner.run(self.compose + ['config', '--quiet'], timeout=25)

    def address(self):
        if self.args.ip:
            return str(ipaddress.IPv4Address(self.args.ip))
        if self.args.tailscale:
            self.dependency('tailscale', 'https://tailscale.com/install.sh')
            raw = self.runner.run(['tailscale', 'ip', '-4'], capture=True, check=False, timeout=15)
            try:
                return str(ipaddress.IPv4Address(raw))
            except (ValueError, TypeError):
                raise SetupError('Connect Tailscale first with sudo tailscale up, then retry; or use LAN setup without --tailscale.') from None
        # Keep a previously chosen address on reruns unless explicitly overridden.
        env = ROOT / '.env'
        if env.is_file():
            for line in env.read_text(encoding='utf-8').splitlines():
                if line.startswith('AEGIS_HOST_IP='):
                    try:
                        return str(ipaddress.IPv4Address(line.split('=', 1)[1].strip()))
                    except ValueError:
                        pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(('192.0.2.1', 53))  # Route selection only; no packet is sent.
                return sock.getsockname()[0]
        except OSError:
            self.ui.warn('No LAN address found. Using loopback; set --ip for a reachable LAN address.')
            return '127.0.0.1'

    def cli(self, command):
        # Pin Compose to the project already inspected; the CLI honours these variables.
        project = self.compose[self.compose.index('--project-name')+1] if '--project-name' in self.compose else None
        if project:
            os.environ['COMPOSE_PROJECT_NAME'] = project
        files = [self.compose[i+1] for i,x in enumerate(self.compose) if x == '-f']
        os.environ['COMPOSE_FILE'] = os.pathsep.join(files)
        os.environ['AEGIS_SETUP_IP'] = self.selected_ip if hasattr(self, 'selected_ip') else ''
        return self.runner.run(['bash', ROOT / 'aegis', command],
                               interactive=not self.args.yes, timeout=180)

    def ready(self):
        import urllib.request
        import urllib.error
        deadline = time.monotonic() + self.args.ready_timeout
        while time.monotonic() < deadline:
            try:
                # A dashboard without authentication is not a successful installation.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                try:
                    opener.open('http://127.0.0.1:5380/api/stats', timeout=2)
                    raise SetupError('The dashboard answered without authentication; stop and inspect its configuration.')
                except urllib.error.HTTPError as error:
                    if error.code != 401:
                        raise OSError('Dashboard is not ready') from error
                states = self.runner.run(self.docker + ['inspect', '--format', '{{.State.Running}} {{.State.Restarting}}', 'aegisdns', 'openroot'], capture=True, timeout=10).splitlines()
                if states == ['true false', 'true false'] and dns_check(tcp=False) and dns_check(tcp=True):
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(1)
        raise SetupError('DNS did not pass UDP/TCP checks before the timeout. Check outbound DNS access, port 53, and the saved log. Your data is retained.')

    def install(self):
        self.ui.step(1, 6, 'Check this machine')
        self.requirements()
        self.ui.say(f'Install from {ROOT}')
        if not WINDOWS and not self.args.no_start:
            self.ui.say('This changes this host’s DNS. Your router and other devices are untouched.')
        if self.args.install_deps:
            self.ui.say('Missing Docker or requested Tailscale will be installed using official scripts.')
        if not self.ui.confirm('Continue with this plan?', self.args.yes, default=True):
            self.ui.say('Setup cancelled. Thank you for considering AegisDNS.'); return
        self.ui.step(2, 6, 'Connect to Docker')
        self.connect_docker()
        self.ui.done('Docker and Compose are available')
        if not WINDOWS:
            self.sudo()  # Obtain permission before the long build, never behind a spinner.
            target = CLI_LINK
            if (target.exists() or target.is_symlink()) and (not target.is_symlink() or target.resolve() != ROOT / 'aegis'):
                raise SetupError('/usr/local/bin/aegis belongs to something else. It will not be replaced.')
        self.ui.step(3, 6, 'Prepare your configuration')
        self.selected_ip = self.address()
        if not self.args.yes and not self.args.ip:
            try:
                answer = input(f'  Server IPv4 [{self.selected_ip}]: ').strip()
            except EOFError:
                raise SetupError('Input closed before configuration was saved.') from None
            if answer:
                parsed_ip = ipaddress.IPv4Address(answer)
                if parsed_ip.is_multicast or parsed_ip.is_unspecified or str(parsed_ip) == '255.255.255.255':
                    raise SetupError('Choose a usable server IPv4 address.')
                self.selected_ip = str(parsed_ip)
        prepare_config(ROOT, self.selected_ip, self.backup)
        self.ui.done(f'DNS address: {self.selected_ip}. Existing settings preserved.')
        self.runner.run(self.compose + ['config', '--quiet'], timeout=25)
        self.ui.step(4, 6, 'Build AegisDNS')
        self.ui.say('The first build may take a few minutes.')
        self.runner.run(self.compose + ['build'] + (['--no-cache'] if self.args.rebuild else []), timeout=self.args.build_timeout)
        self.runner.run(self.compose + ['run', '--rm', '--no-deps', '--user', '10001:10001', '--entrypoint', '/bin/sh', 'aegisdns', '-c', 'test -r /app/config.json && test -r /var/lib/aegisdns/openroot.json'], timeout=60)
        self.ui.done('Images and configuration verified')
        self.ui.step(5, 6, 'Install the command')
        if not WINDOWS:
            # This command may prompt even after validation when sudoers uses a
            # zero-length timestamp. Never force a cached credential here.
            self.sudo_run('ln', '-sfn', str(ROOT / 'aegis'), CLI_LINK, timeout=15)
        self.ui.done('Use aegis for daily control' if not WINDOWS else 'Use Docker Compose for daily control on Windows')
        self.ui.step(6, 6, 'Start and verify' if not self.args.no_start else 'Leave ready to start')
        if not self.args.no_start:
            self.started = True
            if WINDOWS:
                self.runner.run(self.compose + ['up', '-d'], timeout=180)
            else:
                self.cli('restart')
            self.ui.say('Checking dashboard and DNS…')
            self.ready()
            self.started = False
            self.ui.done('DNS is answering; dashboard is protected')
        print()
        self.ui.say(self.ui.ink('AegisDNS is ready', '1;32'))
        if self.args.no_start:
            self.ui.say('Start when ready: docker compose up -d' if WINDOWS else 'Start when ready: aegis start')
        else:
            self.ui.say('Dashboard   http://localhost:5380')
        self.ui.say('Credentials docker exec aegisdns cat /var/lib/aegisdns/admin-password' if WINDOWS else 'Credentials aegis credentials')
        self.ui.say(f'DNS address {self.selected_ip}')
        self.ui.say('Next: test this address on one device.')

    def uninstall(self):
        self.ui.step(1, 4, 'Review removal')
        self.requirements()
        self.ui.say('Before removal, move any devices or router settings that use this server to another DNS resolver.')
        self.ui.say('Remove: this installation’s containers and its matching CLI link.')
        self.ui.say('Delete: Docker data volume (rules, devices, history, credentials).' if self.args.purge else 'Keep: stored data, configuration, images, and source files.')
        self.ui.say('Docker, Tailscale, and other applications remain installed.')
        if not self.ui.confirm('Remove AegisDNS?', self.args.yes, word='DELETE' if self.args.purge else None):
            self.ui.say('Removal cancelled. Nothing was removed.'); return
        self.ui.step(2, 4, 'Stop this installation')
        self.connect_docker()
        self.runner.run(self.compose + ['down'], timeout=180)
        self.ui.done('Containers removed')
        self.ui.step(3, 4, 'Restore host DNS')
        if not WINDOWS:
            self.cli('restore-dns')
        self.ui.done('Host DNS restoration completed' if not WINDOWS else 'Windows host DNS was not modified by this installer')
        # Do not purge data or remove recovery tools if stopping/restoring failed.
        self.ui.step(4, 4, 'Finish cleanup')
        if self.args.purge:
            self.runner.run(self.compose + ['down', '--volumes'], timeout=90)
            self.ui.done('Compose-managed data removed. Local configuration and blocklist files remain.')
        if not WINDOWS:
            target = CLI_LINK
            if target.is_symlink() and target.resolve() == ROOT / 'aegis':
                self.sudo_run('rm', '--', target, timeout=15)
            elif target.exists() or target.is_symlink():
                self.ui.warn('The aegis command belongs to another installation; it was left in place.')
        print()
        self.ui.say(self.ui.ink('AegisDNS removed', '1;32'))
        self.ui.say('Source and configuration remain in this directory.')

    def recover(self):
        if not self.started:
            return
        self.ui.warn('Startup did not finish. Stopping this installation and restoring host DNS; stored data is kept.')
        try:
            if WINDOWS:
                self.runner.run(self.compose + ['down'], timeout=90)
            else:
                self.cli('stop')
            self.ui.done('Startup rolled back')
        except Exception as error:
            self.ui.warn(f'Recovery needs attention: {error}. Keep .dns-backup and run aegis stop after resolving the error.')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='AegisDNS terminal installer and uninstaller. LAN setup is the default.')
    parser.add_argument('action', choices=('install', 'uninstall'))
    parser.add_argument('--yes', '-y', action='store_true', help='accept the reviewed plan; requires working noninteractive sudo on Linux')
    parser.add_argument('--plain', action='store_true', help='plain text, no color or animation')
    parser.add_argument('--purge', action='store_true', help='uninstall: also remove this Compose project’s Docker data')
    parser.add_argument('--ip', help='install: use this server IPv4 address')
    network = parser.add_mutually_exclusive_group()
    network.add_argument('--tailscale', action='store_true', help='install: use an already connected Tailscale address')
    network.add_argument('--no-tailscale', action='store_true', help='install: LAN setup (the default; retained for compatibility)')
    parser.add_argument('--install-deps', action='store_true', help='install missing Docker or requested Tailscale using official scripts')
    parser.add_argument('--no-start', action='store_true', help='build and prepare without changing host DNS or starting DNS services')
    parser.add_argument('--rebuild', action='store_true', help='build without Docker cache')
    parser.add_argument('--allow-desktop', action='store_true', help='acknowledge Docker Desktop host-networking requirements and client-IP limits')
    parser.add_argument('--build-timeout', type=int, default=3600, help='maximum build duration in seconds (default: 3600)')
    parser.add_argument('--ready-timeout', type=int, default=120, help='DNS readiness timeout in seconds (default: 120)')
    args = parser.parse_args(argv)
    if args.purge and args.action != 'uninstall':
        parser.error('--purge is only valid with uninstall')
    if args.action == 'uninstall' and (args.ip or args.tailscale or args.install_deps or args.no_start or args.rebuild):
        parser.error('installation options cannot be used with uninstall')
    if not 10 <= args.ready_timeout <= 600 or not 30 <= args.build_timeout <= 14400:
        parser.error('ready timeout must be 10–600 seconds; build timeout must be 30–14400 seconds')
    if args.ip:
        try:
            address = ipaddress.IPv4Address(args.ip)
            if address.is_unspecified or address.is_multicast or address == ipaddress.IPv4Address('255.255.255.255'):
                raise ValueError()
        except ValueError:
            parser.error('--ip must be a usable server IPv4 address')
    return args


def main(argv=None):
    if sys.version_info < (3, 10):
        print('AegisDNS setup requires Python 3.10 or newer.', file=sys.stderr)
        return 1
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, interrupted)
    args = parse_args(argv)
    ui = UI(args.plain)
    ui.welcome(args.action == 'uninstall')
    setup = None
    try:
        if not args.yes and not sys.stdin.isatty():
            raise SetupError('This terminal has no interactive input. Use --help, then --yes after reviewing the plan.')
        with setup_lock(ROOT):
            state = Path(os.environ.get('LOCALAPPDATA' if WINDOWS else 'XDG_STATE_HOME') or (Path.home() / '.local/state')) / 'aegisdns'
            if state.is_symlink():
                raise SetupError('The setup state directory must not be a symlink.')
            state.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not WINDOWS:
                if state.stat().st_uid != os.getuid():
                    raise SetupError('The setup state directory belongs to another user.')
                state.chmod(0o700)
            backup = Path(tempfile.mkdtemp(prefix=f'{args.action}-', dir=state))
            log = backup / 'setup.log'
            log.touch(mode=0o600)
            setup = Setup(args, ui, Runner(ui, log), backup)
            if args.action == 'install':
                setup.install()
            else:
                setup.uninstall()
        return 0
    except (KeyboardInterrupt, SetupError, OSError, ValueError, subprocess.SubprocessError) as error:
        print()
        ui.warn('Cancelled by you.' if isinstance(error, KeyboardInterrupt) else str(error))
        if setup:
            setup.recover()
        ui.say('Fix the reported issue and rerun the same command. Existing data is retained unless an explicit purge completed.')
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    finally:
        if ui.tty:
            print('\033[?25h', end='', flush=True)


if __name__ == '__main__':
    sys.exit(main())
