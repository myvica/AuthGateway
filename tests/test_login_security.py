import io
import logging
import os
import unittest

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_DB = os.path.join(_PROJECT_DIR, 'data', 'test.db')
if os.path.exists(_TEST_DB):
    os.remove(_TEST_DB)
os.environ['DATABASE_URL'] = 'sqlite:///data/test.db'

import pyotp

import app as app_module
from app import app
from users import add_user


def post_login(client, ip, username, code='000000'):
    return client.post(
        '/',
        data={'username': username, 'totp_code': code},
        environ_base={'REMOTE_ADDR': ip},
    )


def wrong_code_for(secret):
    right = int(pyotp.TOTP(secret).now())
    return f'{(right + 1) % 1000000:06d}'


class LoginRateLimitTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_lockout_after_failures(self):
        ip = '198.51.100.1'
        for _ in range(5):
            response = post_login(self.client, ip, 'nosuchuser')
            self.assertEqual(response.status_code, 200)
        html = post_login(self.client, ip, 'nosuchuser').get_data(as_text=True)
        self.assertIn('尝试次数过多', html)

    def test_other_ip_not_locked_by_username_spam(self):
        # 用户名维度不封锁：攻击者刷某账号失败不得影响其他来源登录
        for _ in range(5):
            post_login(self.client, '198.51.100.1', 'victim_user')
        html = post_login(self.client, '198.51.100.2', 'victim_user').get_data(as_text=True)
        self.assertNotIn('尝试次数过多', html)
        self.assertIn('用户名不存在', html)

    def test_success_does_not_reset_counter(self):
        secret = pyotp.random_base32()
        with app.app_context():
            add_user('counter_user', totp_secret=secret, name='计数测试')
        ip = '198.51.100.3'
        for _ in range(3):
            post_login(self.client, ip, 'counter_user', wrong_code_for(secret))
        response = post_login(self.client, ip, 'counter_user', pyotp.TOTP(secret).now())
        self.assertEqual(response.status_code, 302, '正确动态码应登录成功')
        for _ in range(2):
            post_login(self.client, ip, 'counter_user', wrong_code_for(secret))
        html = post_login(self.client, ip, 'counter_user', wrong_code_for(secret)).get_data(as_text=True)
        self.assertIn('尝试次数过多', html, '成功登录不得清空失败计数')


class LogoutTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_get_logout_cannot_clear_session(self):
        # GET 不再触发登出：/logout 仅接受 POST，GET 会被重定向到通用代理路由
        with self.client.session_transaction() as session:
            session['username'] = 'someone'
        response = self.client.get('/logout')
        self.assertNotEqual(response.status_code, 200)
        with self.client.session_transaction() as session:
            self.assertIn('username', session, 'GET 请求不得清除会话')

    def test_legacy_session_without_token_can_logout(self):
        with self.client.session_transaction() as session:
            session['username'] = 'someone'
            session['totp_verified'] = True
        response = self.client.post('/logout')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get('/systems').status_code, 302, '登出后应跳转登录页')

    def test_logout_csrf(self):
        with self.client.session_transaction() as session:
            session['username'] = 'someone'
            session['csrf_token'] = 'tok-1'
        self.assertEqual(
            self.client.post('/logout', data={'csrf_token': 'wrong'}).status_code, 403)
        response = self.client.post('/logout', data={'csrf_token': 'tok-1'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get('/systems').status_code, 302)


class AdminCsrfTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_admin_write_without_csrf_rejected(self):
        with self.client.session_transaction() as session:
            session['username'] = 'admin'
            session['csrf_token'] = 'tok-1'
        self.assertEqual(self.client.delete('/admin/users/x').status_code, 403)
        self.assertEqual(
            self.client.post('/admin/users/x/totp').status_code, 403)


class LoginLogTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_failure_logged_with_sanitized_fields(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(app_module.login_logger.handlers[0].formatter)
        original_handlers = app_module.login_logger.handlers
        app_module.login_logger.handlers = [handler]
        try:
            evil = 'evil\r\nFAKE-LOG-LINE\x1b[31minjected'
            post_login(self.client, '198.51.100.4', evil)
        finally:
            app_module.login_logger.handlers = original_handlers

        content = stream.getvalue()
        self.assertIn('登录失败', content, '失败尝试必须写入登录日志')
        self.assertNotIn('\r', content)
        self.assertNotIn('\nFAKE-LOG-LINE', content, '换行注入必须被过滤')
        self.assertNotIn('\x1b', content, 'ANSI 转义必须被过滤')
        lines = [line for line in content.split('\n') if line.strip()]
        self.assertEqual(len(lines), 1, '一次事件只允许一行日志')


if __name__ == '__main__':
    unittest.main()
