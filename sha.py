# Реализация алгоритма sha-384
def plus(*arg):
    return sum(arg) % (2**64)


def shr(x, n):
    return x >> n


def rotr(x, n):
    return ((x >> n) | (x << (64 - n)))


def ch(x, y, z):
    return (x & y) ^ (~x & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def sigma_0(x):
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)


def sigma_1(x):
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)


def delta_0(x):
    return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7)


def delta_1(x):
    return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6)


def conv_bin(*arg):
    res = ''
    for i in arg:
        res += bin(i)[2:].zfill(64)
    return res


def diff(start, check):
    count = 0
    for i, j in zip(start, check):
        if i != j:
            count += 1
    return count


def chage_bit(number, text):
    if text[number] == '0':
        bit = '1'
    else:
        bit = '0'
    return text[:number] + bit + text[number + 1:]


def diagram(text, bit):
    a, mess = sha384(text)
    b, ch_mess = sha384(text, bit-1)
    result = []
    for m, c in zip(mess, ch_mess):
        result.append(diff(m, c))
    return result


def prepare(text):
    # Преобразование текста в двоичный код
    bin_text = ''.join(format(x, '08b') for x in bytearray(text, 'utf-8'))

    # Вычисления для добавления исходной длины сообщения
    byte_len = len(bin_text)
    bin_byte_len = bin(byte_len)[2::]
    while len(bin_byte_len) != 128: bin_byte_len = '0' + bin_byte_len

    # Добавление дополнительных бит
    bin_text += '1'
    while len(bin_text) % 1024 != 896: bin_text += '0'
    return bin_text + bin_byte_len


def sha384(text, bit=None):
    result = prepare(text)
    if bit != None:result = chage_bit(bit, result)
    # Преобразование двоичного кода в блоки
    M = []
    x = 0
    for i in range(len(result)//1024):
        M.append([])
        m = result[x:x+1024]
        x += 1024
        y = 0
        for j in range(16):
            Mij = int(m[y:y+64], 2)
            M[i].append(Mij)
            y += 64

    # Последовательность 64-битных слов
    key = '''428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc
    3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
    d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2
    72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
    e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
    2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
    983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4
    c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
    27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df
    650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
    a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30
    d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
    19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8
    391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
    748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
    90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
    ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178
    06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
    28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c
    4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817'''
    key.replace('\n', ' ')
    key = key.split()
    for i in range(len(key)): key[i] = int(key[i], 16)
    # Начальные значения хэш-функций
    h0 = int('cbbb9d5dc1059ed8', 16)
    h1 = int('629a292a367cd507', 16)
    h2 = int('9159015a3070dd17', 16)
    h3 = int('152fecd8f70e5939', 16)
    h4 = int('67332667ffc00b31', 16)
    h5 = int('8eb44a8768581511', 16)
    h6 = int('db0c2e0d64f98fa7', 16)
    h7 = int('47b5481dbefa4fa4', 16)
    w = [0]*80 # Список преобразований
    # Основной цикл
    for i in range(len(M)):
        # Подготовка списка преобразований
        for t in range(80):
            if t <= 15:
                w[t] = M[i][t]
            else:
                w[t] = plus(delta_1(w[t - 2]), w[t - 7], delta_0(w[t - 15]), w[t - 16])

        # Инициализация рабочих переменных
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
        check = []
        # Внутренний цикл
        for t in range(80):
            T1 = plus(h, sigma_1(e), ch(e, f, g), key[t], w[t])
            T2 = plus(sigma_0(a), maj(a, b, c))
            h = g
            g = f
            f = e
            e = plus(d, T1)
            d = c
            c = b
            b = a
            a = plus(T1, T2)
            check.append(conv_bin(a, b, c, d, e, f))
        # Вычислние промежуточного значения хэш-функции
        h0 = plus(a, h0)
        h1 = plus(b, h1)
        h2 = plus(c, h2)
        h3 = plus(d, h3)
        h4 = plus(e, h4)
        h5 = plus(f, h5)
        h6 = plus(g, h6)
        h7 = plus(h, h7)
    # Результат
    return [f'{hex(h0)[2:].zfill(16)} {hex(h1)[2:].zfill(16)} {hex(h2)[2:].zfill(16)} {hex(h3)[2:].zfill(16)} {hex(h4)[2:].zfill(16)} {hex(h5)[2:].zfill(16)}', check]
