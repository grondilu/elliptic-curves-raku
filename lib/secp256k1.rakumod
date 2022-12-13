#!/usr/local/bin/raku
unit module secp256k1;

constant p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
constant b = 7;
constant a = 0;

CHECK die "p needs to be prime" unless p.is-prime;

package Modular {
  our sub inverse(Int $n, Int $m = p) returns Int {
    if $m.is-prime { expmod $n, $m - 2, $m }
    else {
      my Int ($c, $d, $uc, $vc, $ud, $vd) = ($n % $m, $m, 1, 0, 0, 1);
      my Int $q;
      while $c != 0 {
	($q, $c, $d) = ($d div $c, $d % $c, $c);
	($uc, $vc, $ud, $vd) = ($ud - $q*$uc, $vd - $q*$vc, $uc, $vc);
      }
      return $ud < 0 ?? $ud + $m !! $ud;
    }
  }
}

class Point is export {
    has Int ($.x, $.y, $.order);
    submethod TWEAK { $!x %= p; $!y %= p; }
    multi method new
    (
	Int:D $x,
	Int:D $y where ($y**2 - ($x**3 + a*$x + b)) %% p,
	Int :$order?
    ) { samewith :x($x % p), :y($y % p), :$order }
    multi method new(Blob $b where $b.elems == 33 && $b[0] == 2|3) {
      my $x = $b.subbuf(1).reduce: 256 xx *;
      my $y = ($x**3 + a*$x + b) % p;
      $y = -$y % p if $y %% 2 && $b[0] == 3;
      samewith :$x, :$y
    }
    multi method gist(::?CLASS:D:) { "EC Point at x=$.x, y=$.y" }
    multi method gist(::?CLASS:U:) { "point at horizon" }
    multi method Blob { blob8.new: ($!y %% 2 ?? 2 !! 3), $!x.polymod(256 xx 31).reverse }
    multi method Blob(:$uncompressed where ?*) {
      blob8.new: 0x04, ($!x, $!y).map: *.polymod(256 xx 31).reverse
    }
}

our constant G is export = Point.new:
0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
:order(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141);

multi sub infix:<eqv>(Point $a, Point $b) returns Bool is export { $a.x == $b.x && $a.y == $b.y }
multi sub prefix:<->(Point:U) { Point }
multi sub prefix:<->(Point:D $point) {
    Point.new: :x($point.x), :y(-$point.y % p), :order($point.order);
}
multi infix:<->(Point $a, Point $b) { $a + -$b }

multi infix:<*>(Point $u, Int $n) is export { $n * $u }
multi infix:<*>(Int $n, Point:U) is export { Point }
multi infix:<*>(0, Point)          is export { Point }
multi infix:<*>(1, Point:D $point) is export { $point }
multi infix:<*>(2, Point:D $point) is export {
    my Int $l = (3*$point.x**2 + a) * Modular::inverse(2 *$point.y) % p;
    my Int $x = ($l**2 - 2*$point.x) % p;
    my Int $y = ($l*($point.x - $x) - $point.y) % p;
    if defined $point.order {
	Point.new:
	:$x, :$y, :order($point.order %% 2 ?? $point.order div 2 !! $point.order);
    }
    else { Point.new: :$x, :$y }
}

multi infix:<*>(Int $n where $n > 2, Point:D $point) is export {
  2 * ($n div 2 * $point) + $n % 2 * $point;
}

multi infix:<+>(Point:U, Point $b)   is export { $b }
multi infix:<+>(Point:D $a, Point:U) is export { $a }
multi infix:<+>(Point:D $a, Point:D $b) is export {
    if ($a.x - $b.x) %% p {
	return ($a.y + $b.y) %% p ?? Point !! 2 * $a;
    }
    else {
	my $i = Modular::inverse($b.x - $a.x);
	my $l = ($b.y - $a.y) * $i % p;
	my $x = $l**2 - $a.x - $b.x;
	my $y = $l*($a.x - $x) - $a.y;
	return Point.new: :x($x % p), :y($y % p);
    }
}

package DSA {
    role PublicKey {
	method verify(
	    Buf $h,
	    Int $r where 1..^p,
	    Int $s where 1..^p,
	) {
	    my $c = Modular::inverse $s, my $order = G.order;
	    my @u = map * *$c % $order, reduce(* *256 + *, $h.list), $r;
	    $_ =
		(reduce(* *256 + *, $h.list)*$c % $order) * G +
		($r*$c % $order) * self;
	    !!! 'wrong signature' unless .x % $order == $r; 
	}
    }
    class PrivateKey {
	our $order = G.order;
	has Int $.e;

	method new(Int $e) { self.new: :e($e) } 
	method sign(Buf $h) {

	    # 1. Chose a random number k
	    my Int $k = reduce * *256+*, (^256).roll: ^32;

	    # 2. Compute k * G
	    my Point $point = $k * G;

	    # 3. Compute r s
	    my Int $r = $point.x % $order;
	    my Int $s =
	    Modular::inverse($k, $order) *
	    ($.e * $r + reduce * *256+*, $h.list) % $order
	    ;

	    # 4. Return r s
	    return $r, $s;
	}
	method public_key { $.e * G.clone but PublicKey }
    }
}

# vi: ft=raku
