import threading
import time
from collections import defaultdict, deque


class LoginRateLimiter:
    """内存滑动窗口登录限流器。

    计数保存在进程内存中，gunicorn 多 worker 部署时各 worker 独立计数，
    实际允许的尝试次数约为阈值的 worker 倍数，内网场景可接受。
    """

    # 防止 key 无限增长，超过该数量时清理过期条目
    MAX_KEYS = 10000

    def __init__(self, max_attempts, window_seconds, clock=time.monotonic):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._attempts = defaultdict(deque)
        self._lock = threading.Lock()
        self._clock = clock  # 可注入假时钟便于测试

    def is_blocked(self, key):
        with self._lock:
            self._prune(key)
            return len(self._attempts[key]) >= self.max_attempts

    def record_failure(self, key):
        with self._lock:
            self._prune(key)
            self._attempts[key].append(self._clock())
            if len(self._attempts) > self.MAX_KEYS:
                self._sweep()

    def clear(self, key):
        with self._lock:
            self._attempts.pop(key, None)

    def _prune(self, key):
        now = self._clock()
        queue = self._attempts[key]
        while queue and now - queue[0] > self.window:
            queue.popleft()

    def _sweep(self):
        for key in list(self._attempts.keys()):
            self._prune(key)
            if not self._attempts[key]:
                del self._attempts[key]
