import os
import hashlib
import functools

import ec
from util import randrange
from ec import SECP256k1
from point import Point
import numbertheory

def s(singing_key, key_idx, M, y, G=SECP256k1.generator(), hash_func=hashlib.sha3_256):
    prime_field = SECP256k1.order()
    key_image = singing_key * H2(y[key_idx])
    # Ring signature parameters
    n_keys = len(y)
    random_numbers = [randrange(prime_field) for i in range(n_keys)]
    for i in range(len(random_numbers)):
        print(random_numbers[i])
    alpha = randrange(prime_field)
    L = [0] * n_keys
    R = [0] * n_keys
    c = [0] * n_keys

    # Compute first element of the ring

    L[key_idx] = alpha * G
    R[key_idx] = alpha * H2(y[key_idx])
    c[(key_idx + 1) % n_keys] = H([M, L[key_idx], R[key_idx]], hash_func=hash_func)

    # Iterate for the rest of elements
    i = (key_idx + 1) % n_keys
    while i != key_idx:
        L[i] = random_numbers[i] * G + c[i] * y[i]
        R[i] = random_numbers[i] * H2(y[i]) + c[i] * key_image
        c[(i + 1) % n_keys] = H([M, L[i], R[i]], hash_func=hash_func)
        i = (i + 1) % n_keys

    # Close the ring
    random_numbers[key_idx] = (alpha - c[key_idx] * singing_key) % SECP256k1.order()

    return y, key_image, c[0], random_numbers

def v(message, y, key_image, seed, random_numbers, G=SECP256k1.generator(), hash_func=hashlib.sha3_256):
    # Ring signature parameters
    n_keys = len(y)
    L = [0] * n_keys
    R = [0] * n_keys
    c = [0] * n_keys
    c[0] = seed  # Introduce seed

    # Compute first element of the signature
    L[0] = random_numbers[0] * G + c[0] * y[0]
    R[0] = random_numbers[0] * H2(y[0]) + c[0] * key_image
    c[1] = H([message, L[0], R[0]], hash_func=hash_func)

    # Compute the rest of the ring elements
    i = 1
    while i < n_keys:
        L[i] = random_numbers[i] * G + c[i] * y[i]
        print('here', random_numbers[i])
        print(H2(y[i]))
        R[i] = random_numbers[i] * H2(y[i]) + c[i] * key_image
        c[((i + 1) % n_keys)] = H([message, L[i], R[i]], hash_func=hash_func)
        i = i + 1

    # Compute final element
    print(seed)
    print(c[0])
    return seed == c[0]

def sign(siging_key, key_idx, M, y, G=SECP256k1.generator(), hash_func=hashlib.sha3_256):
    n = len(y)
    c = [0] * n
    s = [0] * n

    # STEP 1

    # STEP 2
    u = randrange(SECP256k1.order())
    c[(key_idx + 1) % n] = H([y, M, G * u], hash_func=hash_func)

    # STEP 3
    for i in [ i for i in range(key_idx + 1, n) ] + [i for i in range(key_idx)]:

        s[i] = randrange(SECP256k1.order())

        z_1 = (G * s[i]) + (y[i] * c[i])

        c[(i + 1) % n] = H([y, M, z_1], hash_func=hash_func)

    # STEP 4
    print('u ' + str(type(u)))
    s[key_idx] = (u - siging_key * c[key_idx]) % SECP256k1.order()
    return (c[0], s)

def verify(message, y, c_0, s, G=SECP256k1.generator(), hash_func=hashlib.sha3_256):
    n = len(y)
    print("c_0 = ", c_0)
    c = [c_0] + [0] * (n - 1)

    for i in range(n):
        z_1 = (G * s[i]) + (y[i] * c[i])

        if i < n - 1:
            c[i + 1] = H([y, message, z_1], hash_func=hash_func)
        else:
            return c_0 == H([y, message, z_1], hash_func=hash_func)

    return False

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

def H(msg, hash_func=hashlib.sha3_256):
    print('String = ', ' hash = ', int('0x'+ hash_func(concat(msg)).hexdigest(), 16))
    return int('0x'+ hash_func(concat(msg)).hexdigest(), 16)

def H2(msg, hash_func=hashlib.sha3_256):
    bytes_value = msg.x().to_bytes(32, 'big') + msg.y().to_bytes(32, 'big')
    return map_to_curve(int('0x' + hash_func(bytes_value).hexdigest(), 16))

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
            print((point[1]))
            keys.append(Point(SECP256k1.p(), SECP256k1.a(), SECP256k1.b(), int(point[0]), int(point[1])))
            line = f.readline()
        return keys

def import_public_key(number, folder_name='./data'):
    file_name = '/public' + str(number) + '.txt'
    with open(folder_name + file_name) as f:
        line = f.readline()
        point = line.rstrip().split(";")
        print(point[0])
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

    x = [randrange(SECP256k1.order()) for i in range(number_participants)]

    y = list(map(lambda xi: SECP256k1.generator() * xi, x))

    z = [randrange(SECP256k1.order()) for i in range(number_participants)]

    j = list(map(lambda zi: SECP256k1.generator() * zi, z))

    signature = sign(x[i], i, message, y)

    export_public_key(y[i], i)
    export_public_keys(y)
    export_private_key(x[i], i)
    export_private_keys(x)
    assert(verify(message, y, *signature))

def import_keys_and_test(number_participants, i, message):
    y = import_public_keys()
    x = import_private_key(i)
    signature = sign(x, i, message, y)
    assert(verify(message, y, *signature))

def main():
    number_participants = 10
    i = 2
    message = "can we talk again"
    x = [randrange(SECP256k1.order()) for i in range(number_participants)]

    y = list(map(lambda xi: SECP256k1.generator() * xi, x))
    keys, key_image, seed, random_numbers = s(x[i], i, message, y)
    print(random_numbers)
    verification = v(message, keys, key_image, seed, random_numbers)
    print(verification)
    #generate_keys_and_test(number_participants, i, message)
    #import_keys_and_test(number_participants, i, message)


if __name__ == '__main__':
    main()