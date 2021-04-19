import os
import hashlib
import functools
import time

import ec
from util import randrange
from ec import curve
from point import Point
import numbertheory

def sign(siging_key, key_idx, M, y, G=curve.generator(), hash_func=hashlib.sha3_256):
    start = time.time()
    n = len(y)
    c = [0] * n
    s = [0] * n

    h = H2(y, hash_func=hash_func)
   # print(h)
    Y = h * siging_key

    u = randrange(curve.order())
    c[(key_idx + 1) % n] = H([y, Y, M, G * u, h * u], hash_func=hash_func)

    for i in [i for i in range(key_idx + 1, n)] + [i for i in range(key_idx)]:
        s[i] = randrange(curve.order())

        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (h * s[i]) + (Y * c[i])

        c[(i + 1) % n] = H([y, Y, M, z_1, z_2], hash_func=hash_func)

    s[key_idx] = (u - siging_key * c[key_idx]) % curve.order()
    end = time.time()
    print("Signature generation: ", end - start)
    return (c[0], s, Y)

def verify(message, y, c_0, s, Y, G=curve.generator(), hash_func=hashlib.sha3_256):
    start = time.time()
    n = len(y)
    c = [c_0] + [0] * (n - 1)

    h = H2(y, hash_func=hash_func)

    for i in range(n):
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (h * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = H([y, Y, message, z_1, z_2], hash_func=hash_func)
        else:
            end = time.time()
            print("Signature verification: ", end - start)
            return c_0 == H([y, Y, message, z_1, z_2], hash_func=hash_func)
    end = time.time()
    print("Signature verification: ", end - start)
    return False

def H(msg, hash_func=hashlib.sha3_256):
    return int('0x'+ hash_func(concat(msg)).hexdigest(), 16)

def map_to_curve(x, P=curve.p()):
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

    return Point(curve.p(), curve.a(), curve.b(), x, y)

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

def export_signature(y, message, signature, folder_name='./data', file_name='signature.txt'):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    arch = open(folder_name + "/" + file_name, 'w')
    S = ''.join(map(lambda x: str(x) + ';', signature[1]))[:-1]
    Y = point_to_string(signature[2])

    dump = '{}\n'.format(signature[0])
    dump += '{}\n'.format(S)
    dump += '{}\n'.format(Y)

    arch.write(dump)

    pub_keys = ''.join(map(lambda yi: point_to_string(yi) + ';', y))[:-1]
    data = message + '\n'#'{}\n'.format(''.join([ '{},'.format(m) for m in message])[:-1])
    data += '{}\n,'.format(pub_keys)[:-1]

    arch.write(data)
    arch.close()

def import_signature(path='./data/signature.txt'):
    print(path)
    assert (os.path.exists(path))
    with open(path) as f:
        signature = []

        line = f.readline()
        signature.append(int(line.rstrip()))

        line = f.readline()
        s = [int(i) for i in line.rstrip().split(";")]
        signature.append(s)

        line = f.readline()
        Y = line.rstrip().split(";")
        signature.append(Point(curve.p(), curve.a(), curve.b(), int(Y[0]), int(Y[1])))

        line = f.readline()
        return signature

def export_public_keys(p_keys, folder_name='./data'):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    file_name = 'publics.txt'
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

def export_private_keys(s_keys, folder_name='./data'):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    i = 0
    for key in s_keys:
        arch = open(os.path.join(folder_name, 'secret' + str(i) + '.txt'), 'w')
        arch.write('{}\n'.format(key))
        i = i + 1

    arch.close()

def export_private_key(s_key, number, foler_name='./data'):
    file_name = 'secret' + '.txt'
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')
    arch.write('{}\n'.format(s_key))

    arch.close()

def import_public_keys(path='./data/publics.txt'):
    assert(os.path.exists(path))
    with open(path) as f:
        keys = []
        line = f.readline()
        while line:
            point = line.rstrip().split(";")
            keys.append(Point(curve.p(), curve.a(), curve.b(), int(point[0]), int(point[1])))
            line = f.readline()
        return keys

def import_public_key(number, folder_name='./data'):
    file_name = '/public' + str(number) + '.txt'
    with open(folder_name + file_name) as f:
        line = f.readline()
        point = line.rstrip().split(";")
        return Point(curve.p(), curve.a(), curve.b(), int(point[0]), int(point[1]))

def import_private_key(number, path='./data', fullpath=None):
    if fullpath == None:
        filename = '/secret'+  str(number) + '.txt'
        fullpath = path+filename
    assert(os.path.exists(fullpath))
    with open(fullpath) as f:
        line = f.readline()
        return int(line.rstrip())

def generate_keys(number_participants):
    start = time.time()
    x = [randrange(curve.order()) for i in range(number_participants)]
    y = list(map(lambda xi: curve.generator() * xi, x))
    export_private_keys(x)
    end = time.time()
    print("Keys generation: ", end - start)
    return x, y

def generate_keys_and_test(number_participants, i, message):
    x, y = generate_keys(number_participants)

    start = time.time()
    signature = sign(x[i], i, message, y)
    end = time.time()
    print("Signature generation: ", end - start)
    assert (verify(message, y, *signature))
    message1 = "hi im sleepy"
    signature1 = sign(x[i], i, message1, y)
    print(point_to_string(signature[2]))
    print(point_to_string(signature1[2]))
    export_public_key(y[i], i)
    export_public_keys(y)
    export_private_key(x[i], i)
    export_private_key(x[i], i)

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