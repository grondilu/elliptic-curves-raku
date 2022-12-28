#!/usr/local/bin/raku
unit module secp256k1;

our constant p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

constant b = 7;
constant a = 0;

CHECK {
  die "p is not prime" unless p.is-prime;
  die "p needs to be congruent to 3 modulo 4" unless p - 3 %% 4;
}

class Point is export {

  =for CREDITS
  Implemention using Jacobian coordinates was taken from Wikibooks:
  L<https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates>

  has Int ($.x, $.y, $.z, $.order);
  submethod TWEAK {
    use FiniteField; my $*modulus = p;
    unless self.y**2 == self.x**3 + a*self.x + b {
      die "point is not on the curve (x is {self.x}, y² is {self.y**2 mod p})";
    }
  }
  method jacobian-coordinates { $!x, $!y, $!z }
  method xy { self.x, self.y }
  method WHICH { self.xy.join: '|' }
  multi method new(Int:D $x, Int:D $y, Int :$order?) {
    samewith :$x, :$y, :z(1), :$order
  }
  multi method new(Blob $b where $b.elems == 33 && $b[0] == 2|3) {
    my $x = $b.subbuf(1).list.reduce: 256 * * + *;
    my $y2 = {
      use FiniteField; my $*modulus = p;
      $x**3 + a*$x + b;
    }();
    # L<https://www.rieselprime.de/ziki/Modular_square_root>
    # In order to compute the square root, we will consider different cases,
    # depending on the modulus. When this modulus is odd, we assume that the
    # quantity expmod(a, (m-1) div 2, m) equals 1 (otherwise there is no square
    # root if a ≠ 0 mod m).
    die "Point of abcissa $x can't be on the curve" if expmod($y2, (p-1) div 2, p) !== 1;
    # when m ≡ 3 [mod 4], sqrt = expmod(a, (m - 3) div 4, m)
    my $y = expmod($y2, (p - 3) div 4, p);
    $y = p - $y if $y %% 2 && $b[0] == 3;
    samewith :$x, :$y, :z(1)
  }
  multi method gist(::?CLASS:D:) { "EC Point at x=$.x, y=$.y" }
  multi method gist(::?CLASS:U:) { "point at horizon" }
  multi method Blob { blob8.new: ($.y %% 2 ?? 2 !! 3), $.x.polymod(256 xx 31).reverse }
  multi method Blob(:$uncompressed where ?*) {
    blob8.new: 0x04, ($.x, $.y).map: *.polymod(256 xx 31).reverse
  }
  method Str { "secp256k1::" ~ self.Blob».fmt("%02X").join }

  method x { use FiniteField; my $*modulus = p; $!x/$!z**2 }
  method y { use FiniteField; my $*modulus = p; $!y/$!z**3 }
  method double(--> ::?CLASS) {
    use FiniteField; my $*modulus = p;
    return ::?CLASS if $!y == 0;
    my $s = 4*$!x*$!y**2;
    my $m = 3*$!x**2 + a*$!z**4;
    my $x = $m**2 - 2*$s;
    my $y = $m*($s - $x) - 8*$!y**4;
    my $z = 2*$!y*$!z;
    return self.new: :$x, :$y, :$z;
  }

  method add(::?CLASS $p --> ::?CLASS) {
    use FiniteField; my $*modulus = p;
    my (\X1, \Y1, \Z1) = self.jacobian-coordinates;
    my (\X2, \Y2, \Z2) = $p  .jacobian-coordinates;
    my (\U1, \U2) = X1*Z2**2, X2*Z1**2;
    my (\S1, \S2) = Y1*Z2**3, Y2*Z1**3;
    if U1 == U2 {
      if S1 !== S2 { return ::?CLASS }
      else         { return self.double }
    }
    my \H = U2 - U1;
    my $R = S2 - S1;
    my $x = my \X3 = $R**2 - H**3 - 2*U1*H**2;
    my $y = my \Y3 = $R*(U1*H**2 - X3) - S1*H**3;
    my $z = my \Z3 = H*Z1*Z2;
    return self.new: :$x, :$y, :$z;
  }
}

our constant G is export = Point.new:
  0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
  :order(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141);

multi infix:<*>(2, Point:D $point) is export { $point.double }

multi sub infix:<eqv>(Point $a, Point $b) returns Bool is export { $a.x == $b.x && $a.y == $b.y }
multi sub prefix:<->(Point:U) { Point }
multi sub prefix:<->(Point:D $point) {
    Point.new: :x($point.x), :y(-$point.y), :order($point.order);
}
multi infix:<->(Point $a, Point $b) { $a + -$b }

multi infix:<+>(Point:U, Point $b)   is export { $b }
multi infix:<+>(Point:D $a, Point:U) is export { $a }
multi infix:<+>(Point:D $a, Point:D $b) is export { $a.add: $b }

multi infix:<*>(Point $u, Int $n) is export { $n * $u }
multi infix:<*>(Int $n, Point:U) is export { Point }
multi infix:<*>(0, Point)          is export { Point }
multi infix:<*>(1, Point:D $point) is export { $point }

multi infix:<*>(Int $n where $n < 2**256, Point:D $point) is export {
  [+] $n.polymod(2 xx *) Z* BEGIN (G, 2 * * ... *)[^256]
}

# vi: ft=raku
