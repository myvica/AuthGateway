import os
import unittest

os.environ.setdefault('DATABASE_URL', 'sqlite:///data/test.db')

from app import TrustedProxyFix


def make_environ(peer, forwarded=False):
    environ = {
        'REQUEST_METHOD': 'GET',
        'PATH_INFO': '/',
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        'wsgi.url_scheme': 'http',
        'REMOTE_ADDR': peer,
    }
    if forwarded:
        environ['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 10.0.0.9'
        environ['HTTP_X_FORWARDED_PROTO'] = 'https'
        environ['HTTP_X_FORWARDED_HOST'] = 'gateway.example.com'
    return environ


class CapturingApp:
    def __init__(self):
        self.environ = None

    def __call__(self, environ, start_response):
        self.environ = dict(environ)
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [b'ok']


def run_middleware(peer, forwarded=False):
    captured = CapturingApp()
    middleware = TrustedProxyFix(captured)
    list(middleware(make_environ(peer, forwarded), lambda status, headers: None))
    return captured.environ


class TrustedProxyFixTest(unittest.TestCase):
    def test_trusted_peer_honors_forwarded_headers(self):
        env = run_middleware('127.0.0.1', forwarded=True)
        # PROXY_COUNT=1：取 X-Forwarded-For 右起第 1 个（nginx 追加的真实客户端）
        self.assertEqual(env['REMOTE_ADDR'], '10.0.0.9')
        self.assertEqual(env['wsgi.url_scheme'], 'https')
        self.assertEqual(env.get('HTTP_HOST'), 'gateway.example.com')

    def test_ipv6_loopback_trusted(self):
        env = run_middleware('::1', forwarded=True)
        self.assertEqual(env['REMOTE_ADDR'], '10.0.0.9')

    def test_untrusted_peer_headers_stripped(self):
        env = run_middleware('203.0.113.9', forwarded=True)
        self.assertEqual(env['REMOTE_ADDR'], '203.0.113.9', '不可信对端的来源 IP 不可被伪造')
        self.assertNotIn('HTTP_X_FORWARDED_FOR', env)
        self.assertNotIn('HTTP_X_FORWARDED_PROTO', env)
        self.assertNotIn('HTTP_X_FORWARDED_HOST', env)
        self.assertEqual(env['wsgi.url_scheme'], 'http')

    def test_no_forwarded_headers_passthrough(self):
        env = run_middleware('203.0.113.9')
        self.assertEqual(env['REMOTE_ADDR'], '203.0.113.9')

    def test_invalid_peer_address_not_trusted(self):
        env = run_middleware('not-an-ip', forwarded=True)
        self.assertEqual(env['REMOTE_ADDR'], 'not-an-ip')
        self.assertNotIn('HTTP_X_FORWARDED_FOR', env)


if __name__ == '__main__':
    unittest.main()
