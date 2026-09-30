"""Privacy: contextual secret detection. Fake homes only; no test here touches ~/.claude."""
import unittest

from test_collect import collect  # also puts the plugin scripts directory on sys.path
import privacy  # noqa: E402

AWS = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
# (input, secret value, label that must survive, measured entropy in bits/char or None) -- T1-T10
TRUE_POSITIVES = [
    (f'export AWS_SECRET_ACCESS_KEY={AWS}', AWS, 'AWS_SECRET_ACCESS_KEY=', 4.663),
    ('STRIPE_SECRET_KEY=sk_prod_4eC39HqLyjWDarjtT1zdp7dc', 'sk_prod_4eC39HqLyjWDarjtT1zdp7dc',
     'STRIPE_SECRET_KEY=', 4.601),
    ('SECRET_KEY = "Zx9fK2mQ7vL1pR8tW3yB6nD4"', 'Zx9fK2mQ7vL1pR8tW3yB6nD4', 'SECRET_KEY = "', 4.585),
    ('curl --api-token 9fK2mQ7vL1pR8tW3yB6nD4hJ https://api.example.com', '9fK2mQ7vL1pR8tW3yB6nD4hJ',
     '--api-token ', 4.585),
    ('mysql --password hunter22x -h db', 'hunter22x', '--password ', None),
    ('GITHUB_PAT=github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF',
     'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF', 'GITHUB_PAT=', 5.338),
    ('sessionKey: 7Hq2LmX9pRt4VzK8wN3b', '7Hq2LmX9pRt4VzK8wN3b', 'sessionKey: ', 4.322),
    ('curl -H "X-Auth: 3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c" https://x.example',
     '3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c', 'X-Auth: ', 3.906),
    ('https://b.s3.amazonaws.com/f?X-Amz-Signature='
     'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024',
     'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024', 'X-Amz-Signature=', 3.824),
    (f'docker run -e AWS_SECRET_ACCESS_KEY={AWS} app', AWS, 'AWS_SECRET_ACCESS_KEY=', 4.663),
]
MUST_NOT_FLAG = [  # N1-N27
    'git checkout 3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c',
    'commit_sha=3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c',
    'session_id=550e8400-e29b-41d4-a716-446655440000',
    'claude --resume 550e8400-e29b-41d4-a716-446655440000',
    'key_file=/home/user/.ssh/id_ed25519',
    'ssh_key: ~/.ssh/id_ed25519',
    'api_key_env=ANTHROPIC_API_KEY_BACKUP',
    'SIGNING_KEY=PROD_SIGNING_KEY_2026',
    'max_tokens=4096',
    'image=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
    'cacheKey: release-2026-09-29-build',
    'sort_keys=True',
    'hotkey: ctrl+shift+k',
    'session=2026-09-29T10:00:00Z',
    '--token-file ./secrets/ci.token',
    'fingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8',
    'signature_hash=9b74c9897bac770ffc029102a200c5de',
    'session_key=aaaaaaaa11111111',
    'auth_token_2=abababababababab12',
    'KEYBINDINGS=vim',
    '/home/u/code/token-service/src/auth_middleware.py',
    'OPENAI_API_KEY=$(pass show openai)',
    'password_file=/run/secrets/db',
    '--session-id 7c9e6679-7425-40de-944b-e07fc1f90ae7',
    '[metadata-only: 143 chars]',
    'npx jest --passWithNoTests --coverage',
    'psql --password --host db',
]


class ContextualDetection(unittest.TestCase):
    def test_true_positives(self):
        for text, secret, label, _ in TRUE_POSITIVES:
            with self.subTest(text=text[:40]):
                self.assertIn(secret, collect.SECRET_RE.sub('[REDACTED]', text))  # the gap this closes
                out = collect.redact(text)
                self.assertNotIn(secret, out)
                self.assertIn(label + privacy.CONTEXT_TOKEN, out)

    def test_must_not_flag(self):
        for text in MUST_NOT_FLAG:
            with self.subTest(text=text[:40]):
                self.assertEqual(collect.redact(text), text)

    def test_accepted_over_redaction(self):
        text = 'cache_key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        self.assertEqual(collect.redact(text), 'cache_key=' + privacy.CONTEXT_TOKEN)
        self.assertAlmostEqual(privacy.shannon(text.split('=')[1]), 3.786, places=3)

    def test_password_label_already_redacted_by_secret_re_stays_unchanged(self):  # A2
        text = 'password: required'
        first = collect.SECRET_RE.sub('[REDACTED]', text)
        self.assertEqual(privacy.contextual_redact(first), first)  # the contextual pass adds nothing
        self.assertEqual(collect.redact(text), first)

    def test_password_class_uses_last_label_segment(self):
        self.assertTrue(privacy.contextual_secret('PGPASSWORD', 'hunter22x'))
        self.assertTrue(privacy.contextual_secret('--db-password', 'hunter22x'))
        self.assertTrue(privacy.contextual_secret('--pass', 'hunter22x'))
        self.assertFalse(privacy.contextual_secret('--passWithNoTests', 'somevalue'))
        self.assertFalse(privacy.contextual_secret('--password', '--host'))

    def test_measured_entropies(self):
        for text, secret, _, expected in TRUE_POSITIVES:
            if expected is not None:
                with self.subTest(text=text[:40]):
                    self.assertAlmostEqual(privacy.shannon(secret), expected, places=3)
                    self.assertGreaterEqual(privacy.shannon(secret), privacy.ENTROPY_MIN)
        self.assertAlmostEqual(privacy.shannon('aaaaaaaa11111111'), 1.000, places=3)  # N18
        self.assertAlmostEqual(privacy.shannon('abababababababab12'), 1.503, places=3)  # N19

    def test_shannon_reference_values(self):
        self.assertAlmostEqual(privacy.shannon('0123456789abcdef'), 4.0)
        self.assertEqual(privacy.shannon('aaaa'), 0.0)
        self.assertEqual(privacy.shannon(''), 0.0)

    def test_label_segments(self):
        self.assertEqual(privacy.label_segments('sessionKey'), ['session', 'key'])
        self.assertEqual(privacy.label_segments('--api-token'), ['api', 'token'])
        self.assertEqual(privacy.label_segments('AWS_SECRET_ACCESS_KEY'),
                         ['aws', 'secret', 'access', 'key'])

    def test_contextual_search(self):
        self.assertTrue(privacy.contextual_search(f'AWS_SECRET_ACCESS_KEY={AWS}'))
        self.assertFalse(privacy.contextual_search('AWS_PROFILE=dev'))

    def test_sanitize_checks_json_key_value_pairs(self):
        out = collect.sanitize({'AWS_SECRET_ACCESS_KEY': AWS, 'session_cwd': '/tmp/app',
                                'commit_sha': '3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c',
                                'api_key': '$FOO'})
        self.assertEqual(out['AWS_SECRET_ACCESS_KEY'], privacy.CONTEXT_TOKEN)
        self.assertEqual(out['session_cwd'], '/tmp/app')
        self.assertEqual(out['commit_sha'], '3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c')
        self.assertEqual(out['api_key'], '$FOO')


if __name__ == '__main__':
    unittest.main()
