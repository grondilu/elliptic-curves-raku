#!/usr/local/bin/raku
unit module secp256k1;

BEGIN %*ENV<MODULUS> = 
constant p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

constant b = 7;
constant a = 0;


CHECK {
  die "p is not prime" unless p.is-prime;
  die "p needs to be congruent to 3 modulo 4" unless p - 3 %% 4;
}

multi postfix:<⁻¹>(UInt $a) returns UInt { expmod($a, p - 2, p) }
multi infix:</>(Int $a, UInt $b) returns UInt { $a*$b⁻¹ mod p }

class Point is export {

  =for CREDITS
  Implemention using Jacobian coordinates was taken from Wikibooks:
  L<https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates>

  %*ENV<MODULUS> = p;
  has Int ($.x, $.y, $.z, $.order);
  method jacobian-coordinates { $!x, $!y, $!z }
  method xy { self.x, self.y }
  method WHICH { self.xy.join: '|' }
  multi method new(Int:D $x, Int:D $y, Int :$order?) {
    samewith :$x, :$y, :z(1), :$order
  }
  multi method new(Blob $b where $b.elems == 33 && $b[0] == 2|3) {
    my $x = $b.subbuf(1).reduce: 256 xx *;
    my $y2;
    {
      use FiniteFieldArithmetics;
      $y2 = $x**3 + a*$x + b;
    }
    # L<https://www.rieselprime.de/ziki/Modular_square_root>
    my $y = expmod($y2, (p + 1) div 4, p); 
    $y = -$y if $y %% 2 && $b[0] == 3;
    samewith :$x, :$y
  }
  multi method gist(::?CLASS:D:) { "EC Point at x=$.x, y=$.y" }
  multi method gist(::?CLASS:U:) { "point at horizon" }
  multi method Blob { blob8.new: ($!y %% 2 ?? 2 !! 3), $!x.polymod(256 xx 31).reverse }
  multi method Blob(:$uncompressed where ?*) {
    blob8.new: 0x04, ($!x, $!y).map: *.polymod(256 xx 31).reverse
  }

  {
    use FiniteFieldArithmetics;
    method x { $!x/$!z**2 }
    method y { $!y/$!z**3 }
    submethod TWEAK {
      unless self.y**2 == self.x**3 + a*self.x + b {
        note (self.y**2).base(16);
        note (self.x**3 + a*self.x + b).base(16);
	die "point is not on the curve (modulus is {%*ENV<MODULUS>.base(16)})";
      }
    }
    method double(--> ::?CLASS) {

      return ::?CLASS if $!y == 0;
      my $s = 4*$!x*$!y**2;
      my $m = 3*$!x**2 + a*$!z**4;
      my $x = $m**2 - 2*$s;
      my $y = $m*($s - $x) - 8*$!y**4;
      my $z = 2*$!y*$!z;
      return self.new: :$x, :$y, :$z;

    }

    method add(::?CLASS $p --> ::?CLASS) {

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

multi infix:<*>(Point $u, Int $n) is export { $n * $u }
multi infix:<*>(Int $n, Point:U) is export { Point }
multi infix:<*>(0, Point)          is export { Point }
multi infix:<*>(1, Point:D $point) is export { $point }

multi infix:<*>(Int $n where $n > 2, Point:D $point) is export {
  (state %){$n}{$point} //=
  2 * ($n div 2 * $point) + $n % 2 * $point;
}

multi infix:<+>(Point:U, Point $b)   is export { $b }
multi infix:<+>(Point:D $a, Point:U) is export { $a }
multi infix:<+>(Point:D $a, Point:D $b) is export { $a.add: $b }

# vi: ft=raku
