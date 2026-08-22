import os
import tempfile
import time
import unittest

import config


class SecretKeyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key_file = os.path.join(self.tmp.name, 'secret_key')

    def tearDown(self):
        self.tmp.cleanup()

    def test_generates_and_reuses(self):
        key1 = config._load_or_create_secret_key(self.key_file)
        self.assertEqual(len(key1), 64)
        key2 = config._load_or_create_secret_key(self.key_file)
        self.assertEqual(key1, key2, '二次加载必须复用同一密钥')

    def test_empty_file_is_rebuilt(self):
        key1 = config._load_or_create_secret_key(self.key_file)
        with open(self.key_file, 'w'):
            pass  # 模拟写入中途崩溃的空文件残留
        key2 = config._load_or_create_secret_key(self.key_file)
        self.assertEqual(len(key2), 64)
        self.assertNotEqual(key1, key2)
        with open(self.key_file) as f:
            self.assertEqual(f.read().strip(), key2)
        self.assertFalse(os.path.exists(self.key_file + '.lock'), '锁文件必须释放')

    def test_env_takes_precedence(self):
        os.environ['SECRET_KEY'] = 'from-env'
        try:
            self.assertEqual(config._load_or_create_secret_key(self.key_file), 'from-env')
            self.assertFalse(os.path.exists(self.key_file), '环境变量存在时不应写文件')
        finally:
            del os.environ['SECRET_KEY']

    def test_stale_lock_is_taken_over(self):
        config._load_or_create_secret_key(self.key_file)
        with open(self.key_file, 'w'):
            pass  # 弄空
        lock = self.key_file + '.lock'
        with open(lock, 'w') as f:
            f.write('99999')
        stale = time.time() - 60
        os.utime(lock, (stale, stale))
        key = config._load_or_create_secret_key(self.key_file)
        self.assertEqual(len(key), 64, '残留超时的锁应被抢占并完成重建')
        self.assertFalse(os.path.exists(lock))


if __name__ == '__main__':
    unittest.main()
