import socket
import logging
import secrets
import math

hostip = '127.0.0.1'
port = 11111

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
def GCD(a, b):
    while b != 0:
        a, b = b, a % b
    return a
def ModPower(x, y, p):
    res = 1
    x = x % p
    while y > 0:
        if y & 1:
            res = (res * x) % p
        y = y >> 1
        x = (x * x) % p
    return res
def EGCD(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = EGCD(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y
def MulInv(e, phi):
    g, x, y = EGCD(e, phi)
    if g != 1:
        raise Exception('Обратного элемента не существует.')
    else:
        return x % phi
def MillerRabinPrimalityTest(d, n):
    a = 2 + secrets.randbelow(n - 3)
    x = ModPower(a, d, n)
    if x == 1 or x == n - 1:
        return True
    while d != n - 1:
        x = (x * x) % n
        d *= 2
        if x == 1:
            return False
        if x == n - 1:
            return True
    return False
def CheckPrime(n, k=5):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    d = n - 1
    while d % 2 == 0:
        d //= 2
    for i in range(k):
        if not MillerRabinPrimalityTest(d, n):
            return False
    return True
def GeneratePrimeNumber(bits):
    while True:
        maybePrime = secrets.randbits(bits)
        if CheckPrime(maybePrime):
            return maybePrime
def GenerateKeys(k):
    p = GeneratePrimeNumber(k)
    q = GeneratePrimeNumber(k)
    while q == p:
        q = GeneratePrimeNumber(k)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3

    while GCD(e, phi) != 1:
        e += 2
    d = MulInv(e, phi)
    logging.debug(f"Публичный ключ=({e}, {n}), Приватный ключ=({d}, {n})")
    return ((e, n), (d, n))
def Decrypt(pk, text):
    key, n = pk
    blockSize = math.ceil(n.bit_length() / 8)
    decryptedBytes = bytearray()
    for encryptedBlock in text:
        decryptedBlock = ModPower(encryptedBlock, key, n)
        decryptedBytes.extend(decryptedBlock.to_bytes(blockSize, byteorder='big').lstrip(b'\x00'))
    decryptedText = decryptedBytes.decode('utf-8')
    logging.debug(f"Расшифрованный текст: {decryptedText}")
    return decryptedText
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serverSocket:
        serverSocket.bind((hostip, port))
        serverSocket.listen()
        logging.info("Сервер ожидает ввода %s:%d", hostip, port)
        conn, addr = serverSocket.accept()
        with conn:
            logging.info("Подключено: %s", addr)
            publicKey, privateKey = GenerateKeys(1024)
            logging.info("Сервер сгенерировал ключи")
            logging.debug("Публичный ключ сервера: %s, Приватный ключ сервера: %s", publicKey, privateKey)

            conn.sendall(f"{publicKey[0]},{publicKey[1]}".encode())

            encryptedMessage = conn.recv(4096)
            logging.debug("Получено сообщение: %s", encryptedMessage.decode())
            encryptedBlocks = list(map(int, encryptedMessage.decode().split(',')))
            decryptedMessage = Decrypt(privateKey, encryptedBlocks)
            logging.info("Расшифрованное сообщение: %s", decryptedMessage)

if __name__ == "__main__":
    main()