"""Exercise PKCS#12 inspection through the macOS 14 temporary-keychain path."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parent.parent


class SigningHelperCompatibilityTests(unittest.TestCase):
    def test_temporary_keychain_inspection_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='unfairplayed-compat-test-') as folder:
            root = Path(folder)
            binary = root / 'SigningHelper'
            compiled = subprocess.run(['xcrun', 'swiftc', '-swift-version', '5',
                '-target', 'arm64-apple-macos14.0', '-D', 'UNFAIRPLAYED_TEST_LEGACY_IMPORT',
                '-framework', 'Security', '-framework', 'CryptoKit',
                str(ROOT / 'desktop/SigningHelper.swift'), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            name = 'Unfairplayed-Test-' + uuid.uuid4().hex
            cert, key, archive = root / 'cert.pem', root / 'key.pem', root / 'identity.p12'
            commands = [
                ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-subj', '/CN=' + name, '-keyout', str(key), '-out', str(cert)],
                ['openssl', 'pkcs12', '-export', '-inkey', str(key), '-in', str(cert),
                 '-out', str(archive), '-passout', 'pass:fixture-password'],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            def search_identity():
                result = subprocess.run(['/usr/bin/security', 'find-certificate', '-a', '-c', name],
                                        capture_output=True, text=True)
                return result.returncode, result.stdout
            before = search_identity()
            keychains_before = subprocess.check_output(['/usr/bin/security', 'list-keychains', '-d', 'user'])
            env = dict(os.environ, TMPDIR=str(root) + '/', UNFAIRPLAYED_TEST_LEGACY_IMPORT='1')
            def inspect(password):
                request = json.dumps({'action': 'inspect', 'p12': str(archive), 'password': password}).encode()
                return subprocess.run([str(binary)], input=request, capture_output=True, env=env, timeout=30)
            result = inspect('fixture-password')
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            identity = json.loads(result.stdout)
            self.assertEqual(identity['name'], name)
            self.assertEqual(len(identity['sha1']), 40)
            self.assertFalse(list(root.glob('unfairplayed-inspect-*')))
            self.assertNotEqual(inspect('wrong-password').returncode, 0)
            self.assertFalse(list(root.glob('unfairplayed-inspect-*')))
            env.pop('UNFAIRPLAYED_TEST_LEGACY_IMPORT')
            native = inspect('fixture-password')
            self.assertEqual(native.returncode, 0, native.stderr.decode(errors='replace'))
            self.assertEqual(json.loads(native.stdout)['sha1'], identity['sha1'])
            self.assertFalse(list(root.glob('unfairplayed-inspect-*')))
            self.assertEqual(search_identity(), before)
            self.assertEqual(subprocess.check_output(['/usr/bin/security', 'list-keychains', '-d', 'user']), keychains_before)


if __name__ == '__main__':
    unittest.main()
