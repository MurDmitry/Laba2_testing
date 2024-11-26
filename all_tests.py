import unittest
from math import gcd
from rsa_module import PrimeGenerator, RSAEncryption


# Блочное тестирование (Первый класс PrimeGenerator)
class TestPrimeGenerator(unittest.TestCase):
    def setUp(self):
        self.prime_gen = PrimeGenerator()

    def test_is_prime(self):
        """Является ли число простым?"""
        self.assertTrue(self.prime_gen._is_prime(7))        # Число 7 простое (True)
        self.assertTrue(self.prime_gen._is_prime(11273))    # Число 11273 простое (True)
        self.assertFalse(self.prime_gen._is_prime(11424))   # Число 11424 непростое (False)
        self.assertFalse(self.prime_gen._is_prime(1))       # Число 1 непростое (False)

    def test_is_prime_negative(self):
        """Является ли число простым?"""
        self.assertFalse(self.prime_gen._is_prime(-1))        # Число -1 непростое (False)
        self.assertFalse(self.prime_gen._is_prime(-8999))    # Число -8999 непростое (False)
        self.assertFalse(self.prime_gen._is_prime(-17234))   # Число -17234 непростое (False)

    def test_generate_prime(self):
        """Сгенерированное число простое?"""
        for i in range(4):
            prime = self.prime_gen.generate_prime()
            self.assertTrue(self.prime_gen._is_prime(prime))

    def test_generate_distinct_primes(self):
        """Числа p и q разные?"""
        p, q = self.prime_gen.generate_distinct_primes()
        self.assertNotEqual(p, q)
        self.assertTrue(self.prime_gen._is_prime(p))
        self.assertTrue(self.prime_gen._is_prime(q))


# Блочное тестирование (Второй класс RSAEncryption)
class TestRSAEncryption(unittest.TestCase):
    def setUp(self):
        self.rsa = RSAEncryption()

    def test_extended_euclid(self):
        """Проверка работы расширенного алгоритма Евклида"""
        d, x, y = self.rsa._extended_euclid(30, 50)
        self.assertEqual(d, gcd(30, 50))
        self.assertEqual(30 * x + 50 * y, d)


# Интеграционные тесты
class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.rsa = RSAEncryption()

    def test_key_generation(self):
        """Генерация ключей (в целом), проверка на непустоту и > 0"""
        e = 7
        public_key, private_key, p, q = self.rsa.generate_key(e)
        self.assertIsNotNone(public_key)        # Значение непустое
        self.assertIsNotNone(private_key)       # Значение непустое
        self.assertNotEqual(p, q)               # p и q разные
        self.assertGreater(public_key[1], 0)    # Значения больше 0
        self.assertGreater(private_key[0], 0)   # Значения больше 0
    
    def test_encryption_bad_e(self):
        """ Проверка, число e отрицательное """
        e = -9
        public_key, private_key, p, q = self.rsa.generate_key(e)
        self.assertIsNotNone(public_key)        # Значение непустое
        self.assertIsNotNone(private_key)       # Значение непустое
        self.assertNotEqual(p, q)               # p и q разные
        self.assertGreater(public_key[1], 0)    # Значения больше 0
        self.assertGreater(private_key[0], 0)   # Значения больше 0

    def test_encryption_decryption(self):
        """Шифровка и расшифровка одного и того же сообщения"""
        e = 7
        data = 1234
        public_key, private_key, _, _ = self.rsa.generate_key(e)
        encrypted_data = self.rsa.encrypt(data, public_key)
        decrypted_data = self.rsa.decrypt(encrypted_data, private_key)
        self.assertEqual(decrypted_data, data)

    def test_encryption_different_data(self):
        """Шифровка разных сообщений"""
        e = 7
        data1 = 123
        data2 = 456
        public_key, private_key, _, _ = self.rsa.generate_key(e)
        encrypted_data1 = self.rsa.encrypt(data1, public_key)
        encrypted_data2 = self.rsa.encrypt(data2, public_key)
        self.assertNotEqual(encrypted_data1, encrypted_data2)

    def test_public_private_key_different(self):
        """Рахные ключи"""
        e = 7
        public_key1, private_key1, _, _ = self.rsa.generate_key(e)
        public_key2, private_key2, _, _ = self.rsa.generate_key(e)
        self.assertNotEqual(public_key1, public_key2)
        self.assertNotEqual(private_key1, private_key2)


# Аттестационное тестирование
class TestAcceptance(unittest.TestCase):
    def setUp(self):
        self.rsa = RSAEncryption()

    def test_system_flow(self):
        """Проверка полного цикла шифрования/дешифрования"""
        e = 7
        data = 5678
        public_key, private_key, _, _ = self.rsa.generate_key(e)
        encrypted_data = self.rsa.encrypt(data, public_key)
        decrypted_data = self.rsa.decrypt(encrypted_data, private_key)
        self.assertEqual(decrypted_data, data)

    def test_encryption_speed(self):
        """Скорость выполения"""
        import time
        e = 7
        data = 123456789
        public_key, private_key, _, _ = self.rsa.generate_key(e)
        start_time = time.time()
        encrypted_data = self.rsa.encrypt(data, public_key)
        decrypted_data = self.rsa.decrypt(encrypted_data, private_key)
        end_time = time.time()
        self.assertTrue(end_time - start_time < 5)

    def test_valid_keys(self):
        e = 7
        public_key, private_key, p, q = self.rsa.generate_key(e)
        self.assertTrue(all(isinstance(x, int) for x in public_key))
        self.assertTrue(all(isinstance(x, int) for x in private_key))

    def test_negative_data(self):
        """Работа с отрицательными числами"""
        e = 7
        data = -54321
        public_key, private_key, _, _ = self.rsa.generate_key(e)
        encrypted_data = self.rsa.encrypt(data, public_key)
        decrypted_data = self.rsa.decrypt(encrypted_data, private_key)
        self.assertNotEqual(decrypted_data, data)     # С отрицательными числами алгоритм работать не будет

    def test_zero_data(self):
        """Работа c 0"""
        e = 7
        data = 0
        public_key, private_key, _, _ = self.rsa.generate_key(e)
        encrypted_data = self.rsa.encrypt(data, public_key)
        decrypted_data = self.rsa.decrypt(encrypted_data, private_key)
        self.assertEqual(decrypted_data, data)


if __name__ == '__main__':
    unittest.main()
