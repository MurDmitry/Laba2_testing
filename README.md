[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=MurDmitry_Laba2_testing&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=MurDmitry_Laba2_testing)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=MurDmitry_Laba2_testing&metric=bugs)](https://sonarcloud.io/summary/new_code?id=MurDmitry_Laba2_testing)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=MurDmitry_Laba2_testing&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=MurDmitry_Laba2_testing)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=MurDmitry_Laba2_testing&metric=coverage)](https://sonarcloud.io/summary/new_code?id=MurDmitry_Laba2_testing)
[![Coverage Status](https://coveralls.io/repos/github/MurDmitry/Laba2_testing/badge.svg?branch=main)](https://coveralls.io/github/MurDmitry/Laba2_testing?branch=main)

### Блочные тесты

1. TestPrimeGenerator.test_is_prime
   - **Тип:** Положительный тест
   - **Что проверяет:** Метод \_is\_prime класса PrimeGenerator.
   - **Входные значения:** Простые и непростые числа (7, 11273, 11424, 1).
   - **Ожидаемые выходные значения:** True для простых чисел (7, 11273) и False для непростых (11424, 1).
   - **Описание:** Этот тест проверяет функцию, которая определяет, является ли число простым. Тесты используют как простые, так и непростые числа.

2. TestPrimeGenerator.test_generate_prime
   - **Тип:** Положительный тест
   - **Что проверяет:** Метод generate_prime класса PrimeGenerator.
   - **Входные значения:** Нет входных данных.
   - **Ожидаемые выходные значения:** Простое число.
   - **Описание:** Генерирует случайное простое число и проверяет, действительно ли это число простое.

3. TestPrimeGenerator.test_generate_distinct_primes
   - **Тип:** Положительный тест
   - **Что проверяет:** Метод generate_distinct_primes.
   - **Входные значения:** Нет входных данных.
   - **Ожидаемые выходные значения:** Два различных простых числа.
   - **Описание:** Тестирует, что метод генерирует именно два разных простых числа.

4. TestRSAEncryption.test_extended_euclid
   - **Тип:** Положительный тест
   - **Что проверяет:** Метод \_extended\_euclid класса RSAEncryption.
   - **Входные значения:** Пара чисел (30 и 50).
   - **Ожидаемые выходные значения:** Наибольший общий делитель (НОД) и соответствующие коэффициенты для уравнения.
   - **Описание:** Проверяет, что алгоритм Евклида возвращает корректные коэффициенты и НОД.
  
5. TestPrimeGenerator.test_is_prime_negative
   - **Тип:** Отрицательный тест
   - **Что проверяет:** Метод \_is\_prime класса PrimeGenerator.
   - **Входные значения:** Отрицательные числа (-1, -8999, -17234).
   - **Ожидаемые выходные значения:** False для всех отрицательных значений.
   - **Описание:** Этот тест проверяет функцию, которая определяет, является ли число простым. Тесты используют отрицательные значения.

### Интеграционные тесты

1. TestIntegration.test_key_generation
   - **Тип:** Положительный тест
   - **Что проверяет:** Генерацию ключей методом generate_key.
   - **Входные значения:** Число e (7).
   - **Ожидаемые выходные значения:** Пара (открытый и закрытый ключи).
   - **Описание:** Проверяет, что генерируемые ключи корректны и различны для разных запусков.

2. TestIntegration.test_encryption_decryption
   - **Тип:** Положительный тест
   - **Что проверяет:** Процесс шифрования и дешифрования.
   - **Входные значения:** Число e (7) и данные (1234).
   - **Ожидаемые выходные значения:** Исходные данные после шифрования и расшифровки должны быть идентичны.
   - **Описание:** Проверяет, что полный цикл шифрования и дешифровки работает корректно.

3. TestIntegration.test_encryption_different_data
   - **Тип:** Положительный тест
   - **Что проверяет:** Разницу в зашифрованных данных для разных исходных данных.
   - **Входные значения:** Число e (7) и два различных числа (123, 456).
   - **Ожидаемые выходные значения:** Разные зашифрованные данные.
   - **Описание:** Гарантирует, что разные входные данные приводят к разным зашифрованным результатам.

4. TestIntegration.test_public_private_key_different
   - **Тип:** Положительный тест
   - **Что проверяет:** Различие ключей при разных запусках.
   - **Входные значения:** Число e (7).
   - **Ожидаемые выходные значения:** Различные пары ключей для каждого вызова.
   - **Описание:** Проверяет, что каждый раз с помощью метода generate_key генерируется уникальная пара ключей.
  
5. TestIntegration.test_encryption_bad_e
   - **Тип:** Отрицательный тест
   - **Что проверяет:** Генерацию ключей методом generate_key.
   - **Входные значения:** Число e (-9).
   - **Ожидаемые выходные значения:** Пара (открытый и закрытый ключи).
   - **Описание:** Проверяет, что генерируемые ключи корректны даже при вводе отрицательного значения e.
   
### Аттестационные тесты

1. TestAcceptance.test_system_flow
   - **Тип:** Положительный тест
   - **Что проверяет:** Полный процесс от генерации ключей до шифрования и дешифрования.
   - **Входные значения:** Число e (7) и данные (5678).
   - **Ожидаемые выходные значения:** Декодированные данные совпадают с исходными.
   - **Описание:** Убеждает, что система работает от начала до конца без ошибок.

2. TestAcceptance.test_encryption_speed
   - **Тип:** Негативный тест
   - **Что проверяет:** Скорость выполнения операций шифрования и дешифрования.
   - **Входные значения:** Число e (7) и большие данные (123456789).
   - **Ожидаемые выходные значения:** Весь процесс занимает менее 5 секунд.
   - **Описание:** Обеспечивает работоспособность системы в пределах разумного времени.

3. TestAcceptance.test_valid_keys
   - **Тип:** Положительный тест
   - **Что проверяет:** Корректность типов сгенерированных ключей.
   - **Входные значения:** Число e (7).
   - **Ожидаемые выходные значения:** Все элементы ключей должны быть целыми числами.
   - **Описание:** Проверяет, чтобы все части ключей были целочисленными.

4. **TestAcceptance.test_negative_data**
   - **Тип:** отрицательный
   - **Что проверяет:** Обработка отрицательных данных, которые были введены пользователем.
   - **Входные значения:** Число e (7) и отрицательные данные (-54321).
   - **Ожидаемые выходные значения:** Декодированные данные будут разными.
   - **Описание:** Проверяет, как система справляется с некорректными данными (отрицательными) в процессе шифрования и дешифрования.
  
5. **TestAcceptance.test_zero_data**
   - **Тип:** Положительный тест
   - **Что проверяет:** Обработка нулевого значения.
   - **Входные значения:** Число e (7) и отрицательные данные (0).
   - **Ожидаемые выходные значения:** Декодированные данные будут одинаковыми.
   - **Описание:** Проверяет, как система справляется с нулевыми данными.