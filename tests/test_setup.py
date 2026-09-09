"""Isolated lifecycle tests: no Docker, sudo, host DNS writes or package installs."""
import contextlib
import importlib.util
import io
import json
import os
import signal
import select
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('aegis_setup', SOURCE / 'scripts/setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class FakeRunner:
    def __init__(self, root):
        self.root, self.calls, self.call_options, self.fail = root, [], [], None
        self.owner = None
        self.desktop = False
        self.security = "[]"
        self.files = None
    def run(self, args, **kwargs):
        args = list(map(str, args)); self.calls.append(args); self.call_options.append(kwargs)
        if self.fail and self.fail(args):
            raise setup.SetupError('Simulated operation failure')
        if 'context' in args:
            return 'unix:///var/run/docker.sock'
        if 'info' in args and '{{json .SecurityOptions}}' in args:
            return self.security
        if 'info' in args:
            return 'Docker Desktop' if self.desktop else 'Linux'
        if 'inspect' in args:
            if self.owner is None:
                return '[]'
            return json.dumps([{'Config': {'Labels': {
                'com.docker.compose.project.working_dir': str(self.owner),
                'com.docker.compose.project': 'saved-project',
                'com.docker.compose.project.config_files': self.files or str(self.root/'docker-compose.yml')}}}])
        return '' if kwargs.get('capture') else 0


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backup = self.root / 'backup'; self.backup.mkdir()
        (self.root / 'openroot.example.json').write_text('{}')
        (self.root / 'aegis').touch()
        (self.root / 'docker-compose.yml').touch()
        for name, value in [('ROOT', self.root), ('CLI_LINK', self.root/'bin/aegis'), ('WINDOWS', False)]:
            p = patch.object(setup, name, value); p.start(); self.addCleanup(p.stop)
        p=patch.dict(os.environ);p.start();self.addCleanup(p.stop)
        self.output = io.StringIO(); p=patch('sys.stdout', self.output); p.start(); self.addCleanup(p.stop)
        self.runner = FakeRunner(self.root)
        self.ui = setup.UI(plain=True)

    def flow(self, action='install', *args):
        parsed = setup.parse_args([action, '--yes', '--plain', *args])
        flow = setup.Setup(parsed, self.ui, self.runner, self.backup)
        flow.requirements = lambda: None
        flow.sudo = lambda: ['sudo','-n']
        flow.dependency = lambda *a: None
        flow.ready = lambda: None
        flow.address = lambda: '192.0.2.10'
        return flow

    def test_configuration_preserves_keys_secrets_and_old_addresses(self):
        cfg = {'host_ips':['10.1.1.1'], 'future': {'value':7}}
        (self.root/'config.json').write_text(json.dumps(cfg))
        (self.root/'.env').write_text('SECRET=keep-me\nAEGIS_HOST_IP=old\nexport AEGIS_HOST_IP=duplicate\n# comment\n')
        setup.prepare_config(self.root,'192.0.2.10',self.backup)
        result=json.loads((self.root/'config.json').read_text())
        self.assertEqual(result['future'],cfg['future'])
        self.assertEqual(result['host_ips'],['10.1.1.1','127.0.0.1','192.0.2.10'])
        self.assertEqual((self.root/'.env').read_text(),'SECRET=keep-me\n# comment\nAEGIS_HOST_IP=192.0.2.10\n')
        self.assertEqual(json.loads((self.backup/'config.json').read_text()),cfg)
        self.assertEqual((self.root/'.env').stat().st_mode & 0o777,0o600)
        self.assertEqual((self.root/'config.json').stat().st_mode & 0o777,0o644)
        self.assertNotIn('keep-me',self.output.getvalue())

    def test_invalid_configuration_does_not_rewrite_env(self):
        (self.root/'config.json').write_text('{invalid')
        (self.root/'.env').write_text('KEEP=this\n')
        with self.assertRaises(ValueError): setup.prepare_config(self.root,'192.0.2.10',self.backup)
        self.assertEqual((self.root/'.env').read_text(),'KEEP=this\n')

    def test_invalid_host_ips_rejected(self):
        for bad in ({'host_ips':'string'}, {'host_ips':[3]}, []):
            (self.root/'config.json').write_text(json.dumps(bad))
            with self.assertRaises(setup.SetupError): setup.prepare_config(self.root,'192.0.2.10',self.backup)

    def test_config_symlink_not_followed(self):
        original=self.root/'original';original.write_text('{}')
        (self.root/'config.json').symlink_to(original)
        with self.assertRaises(setup.SetupError): setup.prepare_config(self.root,'192.0.2.10',self.backup)
        self.assertEqual(original.read_text(),'{}')

    def test_invalid_blocklist_path_checked_before_config_changes(self):
        (self.root/'blocklists').write_text('do not replace')
        with self.assertRaises(setup.SetupError): setup.prepare_config(self.root,'192.0.2.10',self.backup)
        self.assertFalse((self.root/'config.json').exists())

    def test_rerun_does_not_duplicate_addresses_or_replace_zones(self):
        (self.root/'openroot.json').write_text('{"mine":true}')
        setup.prepare_config(self.root,'192.0.2.10',self.backup)
        setup.prepare_config(self.root,'192.0.2.10',self.backup)
        self.assertEqual(json.loads((self.root/'config.json').read_text())['host_ips'],['127.0.0.1','192.0.2.10'])
        self.assertEqual((self.root/'openroot.json').read_text(),'{"mine":true}')

    def test_build_only_never_starts_dns_services_or_changes_host_dns(self):
        self.flow('install','--no-start').install()
        self.assertTrue(any('build' in c for c in self.runner.calls))
        self.assertFalse(any(c[0]=='bash' or 'up' in c or 'down' in c for c in self.runner.calls))

    def test_startup_verifies_before_reporting_success(self):
        f=self.flow(); events=[]
        f.ready=lambda: events.append('verified')
        f.install()
        self.assertEqual(events,['verified'])
        self.assertTrue(any(c[-1]=='restart' for c in self.runner.calls))
        self.assertFalse(f.started)
        self.assertIn('DNS is answering', self.output.getvalue())

    def test_interactive_privileged_commands_do_not_require_cached_sudo(self):
        parsed = setup.parse_args(['install', '--plain'])
        flow = setup.Setup(parsed, self.ui, self.runner, self.backup)
        flow.requirements = lambda: None
        flow.sudo = lambda: ['sudo']
        flow.ready = lambda: None
        flow.address = lambda: '192.0.2.10'
        with patch('sys.stdin.isatty', return_value=True), patch('builtins.input', side_effect=['', '']):
            flow.install()
        privileged = [(call, options) for call, options in zip(self.runner.calls, self.runner.call_options)
                      if call and call[0] == 'sudo']
        self.assertTrue(any('ln' in call for call, _ in privileged))
        self.assertTrue(all('-n' not in call for call, _ in privileged))
        self.assertTrue(all(options.get('interactive') for _, options in privileged))
        restart_index = next(i for i, call in enumerate(self.runner.calls) if call[-1] == 'restart')
        self.assertTrue(self.runner.call_options[restart_index].get('interactive'))

    def test_failed_build_leaves_running_service_untouched(self):
        f=self.flow();self.runner.fail=lambda c:'build' in c
        with self.assertRaises(setup.SetupError): f.install()
        f.recover()
        self.assertFalse(any(c[-1] in ('stop','restart') or 'down' in c for c in self.runner.calls))
        self.assertNotIn('Complete',self.output.getvalue())

    def test_failed_readiness_triggers_stop_and_restore(self):
        f=self.flow()
        def fail(): raise setup.SetupError('DNS not ready')
        f.ready=fail
        with self.assertRaises(setup.SetupError): f.install()
        f.recover()
        self.assertEqual(self.runner.calls[-1][-1],'stop')
        self.assertNotIn('--volumes',sum(self.runner.calls,[]))

    def test_uninstall_keeps_data_by_default(self):
        self.flow('uninstall').uninstall()
        self.assertTrue(any('down' in c for c in self.runner.calls))
        self.assertTrue(any(c[-1]=='restore-dns' for c in self.runner.calls))
        self.assertFalse(any('--volumes' in c for c in self.runner.calls))

    def test_purge_uses_saved_compose_project_after_dns_restore(self):
        self.runner.owner=self.root
        self.flow('uninstall','--purge').uninstall()
        purge=next(i for i,c in enumerate(self.runner.calls) if '--volumes' in c)
        restore=next(i for i,c in enumerate(self.runner.calls) if c[-1]=='restore-dns')
        self.assertGreater(purge,restore)
        self.assertIn('saved-project',self.runner.calls[purge])
        self.assertFalse(any('volume' in c for c in self.runner.calls))

    def test_failed_dns_restore_prevents_purge_and_cli_removal(self):
        self.runner.fail=lambda c:c[-1]=='restore-dns'
        with self.assertRaises(setup.SetupError): self.flow('uninstall','--purge').uninstall()
        self.assertFalse(any('--volumes' in c or 'rm' in c for c in self.runner.calls))
        self.assertNotIn('has been removed',self.output.getvalue())

    def test_failed_stop_prevents_restore_and_purge(self):
        self.runner.fail=lambda c:'down' in c
        with self.assertRaises(setup.SetupError): self.flow('uninstall','--purge').uninstall()
        self.assertFalse(any(c[-1]=='restore-dns' or '--volumes' in c for c in self.runner.calls))

    def test_foreign_container_blocks_mutation(self):
        self.runner.owner=self.root/'other-project'
        with self.assertRaisesRegex(setup.SetupError,'another installation'): self.flow().install()
        self.assertFalse(any('build' in c or 'down' in c or 'up' in c for c in self.runner.calls))
        self.assertFalse((self.root/'config.json').exists())

    def test_remote_docker_context_rejected_before_configuration(self):
        with patch.dict(os.environ, {'DOCKER_HOST':'ssh://remote.example'}):
            with self.assertRaisesRegex(setup.SetupError,'local Docker'): self.flow().install()
        self.assertFalse((self.root/'config.json').exists())

    def test_rootless_engine_rejected(self):
        self.runner.security='["name=rootless"]'
        with self.assertRaisesRegex(setup.SetupError,'Rootless'): self.flow().install()
        self.assertFalse((self.root/'config.json').exists())

    def test_owned_compose_overrides_are_preserved(self):
        self.runner.owner=self.root
        overlay=self.root/'docker-compose.extra.yml';overlay.touch()
        self.runner.files=f'{self.root}/docker-compose.yml,{overlay}'
        f=self.flow('uninstall');f.uninstall()
        self.assertIn(str(overlay),f.compose)
        self.assertEqual(os.environ['COMPOSE_FILE'],os.pathsep.join([str(self.root/'docker-compose.yml'),str(overlay)]))

    def test_missing_existing_compose_override_stops_removal(self):
        self.runner.owner=self.root
        self.runner.files=str(self.root/'missing.yml')
        with self.assertRaisesRegex(setup.SetupError,'Compose files'): self.flow('uninstall').uninstall()
        self.assertFalse(any('down' in c for c in self.runner.calls))

    def test_other_cli_link_is_never_replaced(self):
        setup.CLI_LINK.parent.mkdir(); setup.CLI_LINK.write_text('someone else')
        with self.assertRaises(setup.SetupError): self.flow().install()
        self.assertEqual(setup.CLI_LINK.read_text(),'someone else')

    def test_uninstall_leaves_foreign_cli_in_place(self):
        setup.CLI_LINK.parent.mkdir(); setup.CLI_LINK.write_text('someone else')
        self.flow('uninstall').uninstall()
        self.assertFalse(any('rm' in c for c in self.runner.calls))

    def test_desktop_requires_explicit_unattended_acknowledgement(self):
        self.runner.desktop=True
        with self.assertRaises(setup.SetupError): self.flow().install()
        self.assertFalse(any('build' in c for c in self.runner.calls))

    def test_cancelled_plan_performs_no_operations(self):
        self.ui.confirm=lambda *a,**k:False
        self.flow().install()
        self.assertEqual(self.runner.calls,[])

    def test_concurrent_setup_rejected_and_lock_reusable(self):
        with setup.setup_lock(self.root):
            with self.assertRaises(setup.SetupError):
                with setup.setup_lock(self.root): pass
        with setup.setup_lock(self.root): pass

    def test_plain_output_has_no_escape_codes(self):
        self.ui.welcome();self.ui.step(1,6,'Check');self.ui.done('Ready')
        self.assertNotIn('\033',self.output.getvalue())

    def test_legacy_ascii_terminal_falls_back_cleanly(self):
        buffer=io.BytesIO()
        stream=io.TextIOWrapper(buffer, encoding='ascii')
        with patch('sys.stdout',stream):
            self.ui.welcome();self.ui.done('Ready')
            stream.flush()
        self.assertIn(b'OK Ready',buffer.getvalue())

    def test_plain_wrap_fits_narrow_terminal(self):
        with patch('shutil.get_terminal_size',return_value=os.terminal_size((40,24))):
            self.ui.welcome();self.ui.say('A long but useful explanation about installation and recovery.'*3)
        self.assertTrue(all(len(line)<=40 for line in self.output.getvalue().splitlines()))

    def test_runner_failure_and_timeout_keep_output(self):
        log=self.root/'setup.log';log.touch(mode=0o600)
        runner=setup.Runner(self.ui,log)
        with self.assertRaises(setup.SetupError): runner.run([sys.executable,'-c',"print('failure evidence',flush=True);raise SystemExit(7)"])
        with self.assertRaises(setup.SetupError): runner.run([sys.executable,'-c',"import time;print('before timeout',flush=True);time.sleep(5)"],timeout=0)
        self.assertIn('failure evidence',log.read_text())
        self.assertIn('before timeout',log.read_text())

    def test_runner_failed_optional_capture_is_empty(self):
        log=self.root/'setup.log';log.touch()
        self.assertEqual(setup.Runner(self.ui,log).run([sys.executable,'-c',"print('Cannot connect');raise SystemExit(1)"],capture=True,check=False),'')


class TerminalInterrupt(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'PTY process-group test is Unix-specific')
    def test_interrupt_stops_command_and_restores_cursor(self):
        import pty
        with tempfile.TemporaryDirectory() as directory:
            master, slave = pty.openpty()
            code = """import sys, pathlib
sys.path.insert(0, sys.argv[1])
from setup import UI, Runner
ui=UI(); ui.welcome()
try:
    Runner(ui,pathlib.Path(sys.argv[2])).run([sys.executable,'-c','import time;print("command started",flush=True);time.sleep(30)'])
except KeyboardInterrupt:
    sys.exit(130)
"""
            process=subprocess.Popen([sys.executable,'-c',code,str(SOURCE/'scripts'),str(Path(directory)/'log')],stdin=slave,stdout=slave,stderr=slave,start_new_session=True,env=dict(os.environ,TERM='xterm-256color'))
            os.close(slave); data=b''
            try:
                deadline=time.monotonic()+5
                while b'Working' not in data and time.monotonic()<deadline:
                    if select.select([master],[],[],.2)[0]: data+=os.read(master,65536)
                self.assertIn(b'Working',data)
                process.send_signal(signal.SIGINT)
                self.assertEqual(process.wait(timeout=7),130)
                while select.select([master],[],[],.1)[0]:
                    try: data+=os.read(master,65536)
                    except OSError: break
                self.assertIn(b'\x1b[?25l',data)
                self.assertIn(b'\x1b[?25h',data)
                self.assertTrue((Path(directory)/'log').exists())
            finally:
                if process.poll() is None: process.kill();process.wait()
                os.close(master)


class Arguments(unittest.TestCase):
    def test_invalid_or_unsafe_arguments_fail_before_work(self):
        for args in (['install','--purge'],['install','--ip','999.2.3.4'],['install','--ip','0.0.0.0'],['install','--ip','224.0.0.1'],['uninstall','--install-deps'],['install','--ready-timeout','0']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): setup.parse_args(args)
    def test_lan_and_start_are_default(self):
        args=setup.parse_args(['install']); self.assertFalse(args.tailscale); self.assertFalse(args.no_start)
    def test_noninteractive_requires_yes(self):
        with patch('sys.stdin.isatty',return_value=False),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(['install','--plain']),1)


class ShellRecovery(unittest.TestCase):
    def recovery(self, fail=False, incomplete=False):
        with tempfile.TemporaryDirectory() as root:
            backup=Path(root)/'dns';backup.mkdir()
            (backup/'resolv.conf.bak').write_text('nameserver 192.0.2.53\n')
            if not incomplete:(backup/'complete').touch()
            script='''source "$1/aegis"
BACKUP_DIR="$2/dns"
BACKUP_RESOLV="$BACKUP_DIR/resolv.conf.bak"
BACKUP_RESOLV_MODE="$BACKUP_DIR/resolv-mode.bak"
BACKUP_MARKER="$BACKUP_DIR/complete"
BACKUP_STUB="$BACKUP_DIR/stub-state.bak"
BACKUP_STUB_CONFIG="$BACKUP_DIR/stub-config.bak"
BACKUP_RESOLVED_ACTIVE="$BACKUP_DIR/resolved-active.bak"
BACKUP_SYMLINK="$BACKUP_DIR/resolv-symlink.bak"
BACKUP_TAILSCALE="$BACKUP_DIR/tailscale-dns.bak"
sudo() { printf '%s\\n' "$*" >> "$2_UNUSED"; return "$MOCK_SUDO_CODE"; }
restore_dns
'''
            env=dict(os.environ,MOCK_SUDO_CODE='1' if fail else '0',NO_COLOR='1')
            # Function output path is an environment variable, not a positional sudo argument.
            script=script.replace('"$2_UNUSED"','"$MOCK_TRACE"');env['MOCK_TRACE']=str(Path(root)/'trace')
            result=subprocess.run(['bash','-c',script,'test',str(SOURCE),root],capture_output=True,text=True,env=env)
            trace=Path(env['MOCK_TRACE']).read_text() if Path(env['MOCK_TRACE']).exists() else ''
            return result,backup.exists(),trace
    def test_failed_restore_preserves_backup_and_fails(self):
        result,exists,_=self.recovery(fail=True);self.assertNotEqual(result.returncode,0);self.assertTrue(exists)
    def test_success_restores_permissions_and_removes_backup(self):
        result,exists,trace=self.recovery();self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertFalse(exists)
        self.assertIn('cp --remove-destination',trace);self.assertIn('chmod 644 /etc/resolv.conf',trace)
    def test_incomplete_backup_never_changes_host(self):
        result,exists,trace=self.recovery(incomplete=True);self.assertNotEqual(result.returncode,0);self.assertTrue(exists);self.assertEqual(trace,'')


if __name__=='__main__': unittest.main()
