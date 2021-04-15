from point import Point
from util import orderlen

class Curve:
  def __init__(self, p, a, b, Gx, Gy, r):
    self.__p = p
    self.__a = a
    self.__b = b
    self.__generator = Point(self.p(), self.a(), self.b(), Gx, Gy, r)
    self.__order = self.__generator.order()
    self.__baselen = orderlen(self.__order)
    self.__verifying_key_length = 2 * self.__baselen
    self.__signature_length = 2 * self.__baselen

  def curve(self):
    return self.__curve

  def generator(self):
    return self.__generator

  def order(self):
    return self.__order

  def baselen(self):
    return self.__baselen

  def verifying_key_length(self):
    return self.__verifying_key_length

  def signature_length(self):
    return self.__signature_length

  def p(self):
    return self.__p

  def a(self):
    return self.__a

  def b(self):
    return self.__b

  def __str__(self):
    return "CurveFp(p=%d, a=%d, b=%d)" % (self.__p, self.__a, self.__b)

# Certicom secp256-k1
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
r = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

SECP256k1 = Curve(p, a, b, Gx, Gy, r)
curve = SECP256k1