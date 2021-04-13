import numbertheory
from util import orderlen

class Point(object):
  def __init__(self, p, a, b, x, y, order=None):
    self.__curve_p = p
    self.__curve_a = a
    self.__curve_b = b
    self.__x = x
    self.__y = y
    self.__order = order
    if self.__curve_p and self.__curve_a and self.__curve_b:
      assert self.__curve.contains_point(x, y)
    if self.__order:
      assert self * order == INFINITY

  def __eq__(self, other):
    if self.__curve_p == other.__curve_p and self.__curve_a == other.__curve_a and self.__curve_b == other.__curve_b \
       and self.__x == other.__x and self.__y == other.__y:
      return True
    else:
      return False

  def __add__(self, other):
    if other == INFINITY:
      return self
    if self == INFINITY:
      return other
    # assert self.__curve == other.__curve
    if self.__x == other.__x:
      if (self.__y + other.__y) % self.__curve_p == 0:
        return INFINITY
      else:
        return self.double()

    p = self.__curve_p

    l = ((other.__y - self.__y) * \
         numbertheory.inverse_mod(other.__x - self.__x, p)) % p

    x3 = (l * l - self.__x - other.__x) % p
    y3 = (l * (self.__x - x3) - self.__y) % p
    return Point(self.__curve_p, self.__curve_a, self.__curve_b, x3, y3)

  def __mul__(self, other):
    e = other
    if self.__order:
      e = e % self.__order
    if e == 0:
      return INFINITY
    if self == INFINITY:
      return INFINITY
    assert e > 0

    # From X9.62 D.3.2:
    e3 = 3 * e
    negative_self = Point(self.__curve_p, self.__curve_a, self.__curve_b, self.__x, -self.__y, self.__order)
    assert e3 > 0
    result = 1
    while result <= e3:
      result = 2 * result
    i = result // 4
    result = self
    while i > 1:
      result = result.double()
      if (e3 & i) != 0 and (e & i) == 0:
        result = result + self
      if (e3 & i) == 0 and (e & i) != 0:
        result = result + negative_self
      i = i // 2

    return result

  def __rmul__(self, other):
    return self * other

  def double(self):
    """Return a new point that is twice the old."""
    # X9.62 B.3:
    p = self.__curve_p
    a = self.__curve_a

    l = ((3 * self.__x * self.__x + a) * \
         numbertheory.inverse_mod(2 * self.__y, p)) % p

    x3 = (l * l - 2 * self.__x) % p
    y3 = (l * (self.__x - x3) - self.__y) % p

    return Point(self.__curve_p, self.__curve_a, self.__curve_b, x3, y3)

  def contains_point(self, x, y):
    return (y * y - (x * x * x + self.__curve_a * x + self.__curve_b)) % self.__curve_p == 0

  def x(self):
    return self.__x

  def y(self):
    return self.__y

  def curve(self):
    return self.__curve_p, self.__curve_a, self.__curve_b

  def order(self):
    return self.__order

INFINITY = Point(None, None, None, None, None)