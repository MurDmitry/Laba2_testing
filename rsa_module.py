import random
from math import gcd


# Генерация ключей и простых чисел
class PrimeGenerator:
    def __init__(self):
        pass

    def _is_prime(self, num):
        """Protected метод для проверки, является ли число простым."""
        if num < 2:
            return False
        for i in range(2, int(num ** 0.5) + 1):
            if num % i == 0:
                return False
        return True

    def generate_prime(self):
        """Генерирует и возвращает простое число в заданном диапазоне."""
        prime = random.randint(1000, 100000)
        while not self._is_prime(prime):
            prime = random.randint(1000, 100000)
        return prime

    def generate_distinct_primes(self):
        """Генерирует и возвращает два различных простых числа."""
        p = self.generate_prime()
        q = self.generate_prime()
        while p == q:
            q = self.generate_prime()
        return p, q


# Реализация алгоритма RSA
class RSAEncryption:
    def __init__(self):
        self.prime_gen = PrimeGenerator()

    def _extended_euclid(self, a, b):
        """Protected метод для расширенного алгоритма Евклида."""
        if b == 0:
            return a, 1, 0
        else:
            d, x, y = self._extended_euclid(b, a % b)
            return d, y, x - (a // b) * y

    def generate_key(self, e):
        """Генерирует открытые и закрытые ключи для RSA шифрования."""
        t = 2
        while t > 1:
            p, q = self.prime_gen.generate_distinct_primes()
            phi_n = (p - 1) * (q - 1)
            t, x, _ = self._extended_euclid(e, phi_n)
        n = p * q
        d = x % phi_n
        return (e, n), (d, n), p, q

    def encrypt(self, data, public_key):
        """Шифрует данные, используя открытый ключ."""
        e, n = public_key
        c = pow(data, e, n)
        return c

    def decrypt(self, c, private_key):
        """Расшифровывает данные, используя закрытый ключ."""
        d, n = private_key
        m = pow(c, d, n)
        return m


def main():
    rsa_encryption = RSAEncryption()

    e = int(input("Введите число e: "))
    while e % 2 == 0:
        print("Число е должно быть нечетным!")
        e = int(input("Введите число e: "))

    data = int(input("Введите число, которое нужно зашифровать: "))

    public_key, private_key, p, q = rsa_encryption.generate_key(e)

    print("Простое число p:", p)
    print("Простое число q:", q)
    print("Открытый ключ (e, n):", public_key)
    print("Закрытый ключ (d, n):", private_key)

    encrypted_data = rsa_encryption.encrypt(data, public_key)
    print("Зашифрованное число:", encrypted_data)

    decrypted_data = rsa_encryption.decrypt(encrypted_data, private_key)
    print("Расшифрованное число:", decrypted_data)


if __name__ == "__main__":
    main()