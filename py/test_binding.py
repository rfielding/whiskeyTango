"""Cross-language regression: requires Go and Python cryptography."""
import base64
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]

def enc(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')

def dec(value):
    return base64.urlsafe_b64decode(value + '==')

class PythonBindingTest(unittest.TestCase):
    def test_roundtrip_and_signature_reuse(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.exceptions import InvalidTag
        old_args = sys.argv
        try:
            sys.argv = ['wt.py']
            wt = runpy.run_path(str(ROOT / 'py/wt.py'))
        finally:
            sys.argv = old_args
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers()
        n, e, d = private.public_numbers.n, private.public_numbers.e, private.d
        trust = {'keys': [{'kid': 'test', 'kty': 'RSA', 'bits': 2048, 'Nint': n, 'Eint': e}]}
        witness = bytes(range(255))
        nonce = bytes(range(12))
        plaintext = b'{"role":"reader","exp":2000000000}'
        ciphertext = nonce + AESGCM(witness[-32:]).encrypt(nonce, plaintext, None)
        v = int.from_bytes(witness, 'big') ^ int.from_bytes(hashlib.sha256(ciphertext).digest(), 'big')
        signature = pow(v, d, n).to_bytes(256, 'big')
        token = '.'.join([enc(b'test'), enc(ciphertext), enc(signature)])
        self.assertEqual(wt['wt_verify'](trust, token, 0)['role'], 'reader')
        replacement = nonce + AESGCM(witness[-32:]).encrypt(nonce, b'{"role":"admin","exp":2000000000}', None)
        forged = '.'.join([enc(b'test'), enc(replacement), enc(signature)])
        with self.assertRaises(InvalidTag):
            wt['wt_extract_claims'](trust, forged)

@unittest.skipUnless(shutil.which('go'), 'Go compiler required for interoperability test')
class BindingTest(unittest.TestCase):
    def test_go_python_roundtrip_and_signature_reuse(self):
        old_args = sys.argv
        try:
            sys.argv = ['wt.py']
            wt = runpy.run_path(str(ROOT / 'py/wt.py'))
        finally:
            sys.argv = old_args
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'wt')
            signer = str(Path(directory) / 'signer.jwk')
            trusted = str(Path(directory) / 'trusted.jwk')
            subprocess.run(['go', 'build', '-o', binary, './cmd/whiskeyTango'], cwd=ROOT, check=True)
            def cli(*args, data=None):
                return subprocess.run([binary, *args], input=data, text=True, capture_output=True)
            self.assertEqual(cli('-ca', signer, '-kid', 'test', '-create', '-smalle').returncode, 0)
            self.assertEqual(cli('-ca', signer, '-kid', 'test', '-trust', trusted).returncode, 0)
            issued = cli('-ca', signer, '-kid', 'test', '-sign', data='{"role":"reader"}\n')
            self.assertEqual(issued.returncode, 0, issued.stderr)
            token = issued.stdout.strip()
            trust = json.loads(Path(trusted).read_text())
            wt['wt_trust_init'](trust)
            claims = wt['wt_verify'](trust, token, 0)
            self.assertEqual(claims['role'], 'reader')
            self.assertEqual(cli('-ca', trusted, '-verify', data=token+'\n').returncode, 0)
            header, body, signature = token.split('.')
            key = trust['keys'][0]
            v = pow(int.from_bytes(dec(signature), 'big'), key['Eint'], key['Nint'])
            witness = (v ^ int.from_bytes(hashlib.sha256(dec(body)).digest(), 'big')).to_bytes(key['bits']//8-1, 'big')
            claims['role'] = 'admin'
            nonce = bytes(range(12))
            replacement = nonce + AESGCM(witness[-32:]).encrypt(nonce, json.dumps(claims).encode(), None)
            forged = '.'.join([header, enc(replacement), signature])
            from cryptography.exceptions import InvalidTag
            with self.assertRaises(InvalidTag):
                wt['wt_extract_claims'](trust, forged)
            self.assertNotEqual(cli('-ca', trusted, '-verify', data=forged+'\n').returncode, 0)

if __name__ == '__main__':
    unittest.main()
