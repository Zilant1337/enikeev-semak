import socket
import math

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
    return encryptedBlocks
def main():
    hostip = '127.0.0.1'
    port = 11111
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        clientSocket.connect((hostip, port))
        publicKeyData = clientSocket.recv(1024).decode()
        e, n = map(int, publicKeyData.split(','))
        publicKey = (e, n)

        message = "Блаблаблабла тестовый текст 12332158798921658912 ()#$%^&*_-+=[]\\/<>@ смешные символы"
        encryptedMessage = Encrypt(publicKey, message)
        print("Сообщение зашифровано")
        encryptedMessageString = ','.join(map(str, encryptedMessage))
        clientSocket.sendall(encryptedMessageString.encode())
        print("Сообщение отправлено на сервер")

if __name__ == "__main__":
    main()