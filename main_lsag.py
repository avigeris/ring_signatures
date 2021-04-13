import os
import hashlib
import functools
import time

import ec
from util import randrange
from ec import SECP256k1
from point import Point
import numbertheory

def sign(siging_key, key_idx, M, y, G=SECP256k1.generator(), hash_func=hashlib.sha3_256):
    n = len(y)
    c = [0] * n
    s = [0] * n

    # STEP 1
    h = H2(y, hash_func=hash_func)
    Y = h * siging_key

    # STEP 2
    u = randrange(SECP256k1.order())
    c[(key_idx + 1) % n] = H([y, Y, M, G * u, h * u], hash_func=hash_func)

    # STEP 3
    for i in [i for i in range(key_idx + 1, n)] + [i for i in range(key_idx)]:
        s[i] = randrange(SECP256k1.order())

        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (h * s[i]) + (Y * c[i])

        c[(i + 1) % n] = H([y, Y, M, z_1, z_2], hash_func=hash_func)

    # STEP 4
    s[key_idx] = (u - siging_key * c[key_idx]) % SECP256k1.order()
    return (c[0], s, Y)

def verify(message, y, c_0, s, Y, G=SECP256k1.generator(), hash_func=hashlib.sha3_256):
    n = len(y)
    c = [c_0] + [0] * (n - 1)

    h = H2(y, hash_func=hash_func)

    for i in range(n):
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (h * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = H([y, Y, message, z_1, z_2], hash_func=hash_func)
        else:
            return c_0 == H([y, Y, message, z_1, z_2], hash_func=hash_func)

    return False

def H(msg, hash_func=hashlib.sha3_256):
    return int('0x'+ hash_func(concat(msg)).hexdigest(), 16)

def map_to_curve(x, P=SECP256k1.p()):
    x -= 1
    y = 0
    found = False

    while not found:
        x += 1
        f_x = (x * x * x + 7) % P

        try:
            y = numbertheory.square_root_mod_prime(f_x, P)
            found = True
        except Exception as e:
            pass

    return Point(SECP256k1.p(), SECP256k1.a(), SECP256k1.b(), x, y)

def H2(msg, hash_func=hashlib.sha3_256):
    return map_to_curve(H(msg, hash_func=hash_func))

def concat(params):
    n = len(params)
    bytes_value = [0] * n

    for i in range(n):

        if type(params[i]) is int:
            bytes_value[i] = params[i].to_bytes(32, 'big')
        if type(params[i]) is list:
            bytes_value[i] = concat(params[i])
        if type(params[i]) is ec.Point:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')
        if type(params[i]) is str:
            bytes_value[i] = params[i].encode()

        if bytes_value[i] == 0:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')

    return functools.reduce(lambda x, y: x + y, bytes_value)

def point_to_string(p):
    return '{};{}'.format(p.x(), p.y())

def export_signature(y, message, signature, foler_name='./data', file_name='signature.txt'):
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')
    S = ''.join(map(lambda x: str(x) + ',', signature[1]))[:-1]
    Y = point_to_string(signature[2])

    dump = '{}\n'.format(signature[0])
    dump += '{}\n'.format(S)
    dump += '{}\n'.format(Y)

    arch.write(dump)

    pub_keys = ''.join(map(lambda yi: point_to_string(yi) + ';', y))[:-1]
    data = '{}\n'.format(''.join([ '{},'.format(m) for m in message])[:-1])
    data += '{}\n,'.format(pub_keys)[:-1]

    arch.write(data)
    arch.close()

def export_public_keys(p_keys, folder_name='./data', file_name='publics.txt'):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    arch = open(os.path.join(folder_name, file_name), 'w')

    for key in p_keys:
        arch.write('{}\n'.format(point_to_string(key)))

    arch.close()

def export_public_key(p_key, number, foler_name='./data'):
    file_name = 'public' + str(number) + '.txt'
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')
    arch.write('{}\n'.format(point_to_string(p_key)))

    arch.close()

def export_private_keys(s_keys, folder_name='./data', file_name='secrets.txt'):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    arch = open(os.path.join(folder_name, file_name), 'w')

    for key in s_keys:
        arch.write('{}\n'.format(key))

    arch.close()

def export_private_key(s_key, number, foler_name='./data'):
    file_name = 'secret' + str(number) + '.txt'
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')
    arch.write('{}\n'.format(s_key))

    arch.close()

def import_public_keys(folder_name='./data', file_name='/publics.txt'):
    with open(folder_name + file_name) as f:
        keys = []
        line = f.readline()
        while line:
            point = line.rstrip().split(";")
            keys.append(Point(SECP256k1.p(), SECP256k1.a(), SECP256k1.b(), int(point[0]), int(point[1])))
            line = f.readline()
        return keys

def import_public_key(number, folder_name='./data'):
    file_name = '/public' + str(number) + '.txt'
    with open(folder_name + file_name) as f:
        line = f.readline()
        point = line.rstrip().split(";")
        return Point(SECP256k1.p(), SECP256k1.a(), SECP256k1.b(), int(point[0]), int(point[1]))

def import_private_keys(folder_name='./data', file_name='/secrets.txt'):
    with open(folder_name + file_name) as f:
        keys = []
        line = f.readline()
        while line:
            keys.append(int(line.rstrip()))
            line = f.readline()
        return keys

def import_private_key(number, folder_name='./data'):
    file_name = '/secret' + str(number) + '.txt'
    with open(folder_name + file_name) as f:
        line = f.readline()
        return int(line.rstrip())

def generate_keys_and_test(number_participants, i, message):
    start = time.time()
    x = [randrange(SECP256k1.order()) for i in range(number_participants)]
    y = list(map(lambda xi: SECP256k1.generator() * xi, x))
    end = time.time()
    print("Keys generation: ", end - start)

    start = time.time()
    signature = sign(x[i], i, message, y)
    end = time.time()
    print("Signature generation: ", end - start)

    export_public_key(y[i], i)
    export_public_keys(y)
    export_private_key(x[i], i)
    export_private_keys(x)

    start = time.time()
    assert(verify(message, y, *signature))
    end = time.time()
    print("Signature verification: ", end - start)

def import_keys_and_test(number_participants, i, message):
    y = import_public_keys()
    x = import_private_key(i)
    signature = sign(x, i, message, y)
    assert(verify(message, y, *signature))

def main():
    number_participants = 10
    i = 2
    message = "can we talk again"
    generate_keys_and_test(number_participants, i, message)
    import_keys_and_test(number_participants, i, message)


if __name__ == '__main__':
    main()