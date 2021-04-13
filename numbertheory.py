class Error(Exception):
  """Base class for exceptions in this module."""
  pass
class SquareRootError(Error):
  pass
class NegativeExponentError(Error):
  pass


def modular_exp(base, exponent, modulus):
  "Raise base to exponent, reducing by modulus"
  if exponent < 0:
    raise NegativeExponentError("Negative exponents (%d) not allowed" \
                                % exponent)
  return pow(base, exponent, modulus)

def polynomial_multiply_mod(m1, m2, polymod, p):
  prod = (len(m1) + len(m2) - 1) * [0]

  for i in range(len(m1)):
    for j in range(len(m2)):
      prod[i + j] = (prod[i + j] + m1[i] * m2[j]) % p

  assert polymod[-1] == 1

  assert len(polymod) > 1

  while len(prod) >= len(polymod):
    if prod[-1] != 0:
      for i in range(2, len(polymod) + 1):
        prod[-i] = (prod[-i] - prod[-1] * polymod[-i]) % p
    prod = prod[0:-1]

  return prod

def polynomial_exp_mod(base, exponent, polymod, p):
  assert exponent < p

  if exponent == 0:
    return [1]

  G = base
  k = exponent
  if k % 2 == 1:
    s = G
  else:
    s = [1]

  while k > 1:
    k = k // 2
    G = polynomial_multiply_mod(G, G, polymod, p)
    if k % 2 == 1:
      s = polynomial_multiply_mod(G, s, polymod, p)

  return s

def jacobi(a, n):
  assert n >= 3
  assert n % 2 == 1
  a = a % n
  if a == 0:
    return 0
  if a == 1:
    return 1
  a1, e = a, 0
  while a1 % 2 == 0:
    a1, e = a1 // 2, e + 1
  if e % 2 == 0 or n % 8 == 1 or n % 8 == 7:
    s = 1
  else:
    s = -1
  if a1 == 1:
    return s
  if n % 4 == 3 and a1 % 4 == 3:
    s = -s
  return s * jacobi(n % a1, a1)

def square_root_mod_prime(a, p):
  assert 0 <= a < p
  assert 1 < p

  if a == 0:
    return 0
  if p == 2:
    return a

  jac = jacobi(a, p)
  if jac == -1:
    raise SquareRootError("%d has no square root modulo %d" \
                          % (a, p))

  if p % 4 == 3:
    return modular_exp(a, (p + 1) // 4, p)

  if p % 8 == 5:
    d = modular_exp(a, (p - 1) // 4, p)
    if d == 1:
      return modular_exp(a, (p + 3) // 8, p)
    if d == p - 1:
      return (2 * a * modular_exp(4 * a, (p - 5) // 8, p)) % p
    raise RuntimeError("Shouldn't get here.")

  for b in range(2, p):
    if jacobi(b * b - 4 * a, p) == -1:
      f = (a, -b, 1)
      ff = polynomial_exp_mod((0, 1), (p + 1) // 2, f, p)
      assert ff[1] == 0
      return ff[0]
  raise RuntimeError("No b found.")

def inverse_mod(a, m):
  if a < 0 or m <= a:
    a = a % m
  c, d = a, m
  uc, vc, ud, vd = 1, 0, 0, 1
  while c != 0:
    q, c, d = divmod(d, c) + (c,)
    uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
  assert d == 1
  if ud > 0:
    return ud
  else:
    return ud + m
