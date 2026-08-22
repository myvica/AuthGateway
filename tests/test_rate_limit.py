import unittest

from rate_limit import LoginRateLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class LoginRateLimiterTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.limiter = LoginRateLimiter(max_attempts=3, window_seconds=60, clock=self.clock)

    def test_blocks_after_threshold(self):
        for _ in range(3):
            self.limiter.record_failure('ip:1.1.1.1')
        self.assertTrue(self.limiter.is_blocked('ip:1.1.1.1'))
        self.assertFalse(self.limiter.is_blocked('ip:2.2.2.2'), '不应影响其他 IP')

    def test_window_expiry(self):
        for _ in range(3):
            self.limiter.record_failure('ip:1.1.1.1')
        self.clock.advance(61)
        self.assertFalse(self.limiter.is_blocked('ip:1.1.1.1'))

    def test_sliding_window_keeps_recent_failures(self):
        self.limiter.record_failure('ip:1.1.1.1')   # t=1000
        self.clock.advance(50)
        self.limiter.record_failure('ip:1.1.1.1')   # t=1050
        self.clock.advance(9)                        # t=1059：前两条仍在窗口内
        self.limiter.record_failure('ip:1.1.1.1')
        self.assertTrue(self.limiter.is_blocked('ip:1.1.1.1'))
        self.clock.advance(2)                        # t=1061：第一条滑出窗口
        self.assertFalse(self.limiter.is_blocked('ip:1.1.1.1'))

    def test_clear(self):
        for _ in range(3):
            self.limiter.record_failure('ip:1.1.1.1')
        self.limiter.clear('ip:1.1.1.1')
        self.assertFalse(self.limiter.is_blocked('ip:1.1.1.1'))

    def test_sweep_removes_stale_keys(self):
        limiter = LoginRateLimiter(max_attempts=3, window_seconds=60, clock=self.clock)
        for i in range(20):
            limiter._attempts[f'stale:{i}'].append(self.clock.now - 999)
        limiter._attempts['fresh'].append(self.clock.now)
        limiter._sweep()
        self.assertNotIn('stale:0', limiter._attempts)
        self.assertNotIn('stale:19', limiter._attempts)
        self.assertIn('fresh', limiter._attempts)


if __name__ == '__main__':
    unittest.main()
