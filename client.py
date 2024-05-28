import socket
import logging
import math

hostip = '127.0.0.1'
port = 11111

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
def ModPower(x, y, p):
    res = 1
    x = x % p
    while y > 0:
        if y & 1:
            res = (res * x) % p
        y = y >> 1
        x = (x * x) % p
    return res
def Encrypt(pk, text):
    key, n = pk
    blockSize = math.ceil(n.bit_length() / 8) - 1
    byteData = text.encode('utf-8')
    encryptedBlocks = []
    for i in range(0, len(byteData), blockSize):
        block = byteData[i:i + blockSize]
        block = int.from_bytes(block, byteorder='big')
        encrypted_block = ModPower(block, key, n)
        encryptedBlocks.append(encrypted_block)
    logging.debug(f"Зашифрованные блоки: {encryptedBlocks}")
    return encryptedBlocks
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        clientSocket.connect((hostip, port))
        logging.info("Подключение к серверу %s:%d", hostip, port)

        publicKeyData = clientSocket.recv(1024).decode()
        e, n = map(int, publicKeyData.split(','))
        publicKey = (e, n)
        logging.info("Клиент получил публичный ключ.")
        logging.debug("Получен публичный ключ: %s", publicKey)

        message = "Очень длинная строка в UTF8 на 100 символов, включая спец символы вроде 1@#$%^&*()_-+=[]\\/<> и прочие..."
        encryptedMessage = Encrypt(publicKey, message)
        encryptedMessageString = ','.join(map(str, encryptedMessage))
        clientSocket.sendall(encryptedMessageString.encode())
        logging.info("Клиент отправил сообщение.")

if __name__ == "__main__":
    main()