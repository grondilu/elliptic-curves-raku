#!/usr/bin/env raku
unit module Ed25519;

use Digest;
use Digest::SHA;

sub blob-to-int(blob8 $b --> UInt) { [+] $b.list Z[+<] (0, 8 ... *) }

my &H = &sha512;

constant b = 256;
our class Key {...}
our proto verify($message, blob8 $signature where (2*b) div 8, $) {*}

constant p = 2**255 - 19;
constant L = 2**252 + 27742317777372353535851937790883648493;
constant a = -1 + p;

CHECK die "p is not prime" unless p.is-prime;

multi postfix:<⁻¹>(UInt $a) returns UInt { expmod($a, p - 2, p) }
multi infix:</>(Int $a, UInt $b) returns UInt { $a*$b⁻¹ mod p }

constant d = -121665/121666;

package FiniteFieldArithmetics {
  multi prefix:<->(UInt $n          --> UInt) is export { callsame() mod p }
  multi infix:<+> (UInt $a, UInt $b --> UInt) is export { callsame() mod p }
  multi infix:<-> (UInt $a, UInt $b --> UInt) is export { callsame() mod p }
  multi infix:<*> (UInt $a, UInt $b --> UInt) is export { callsame() mod p }
  multi infix:<**>(UInt $a, UInt $b --> UInt) is export { expmod($a, $b, p) }
}

sub bit($h,$i) { ($h[$i div 8] +> ($i%8)) +& 1 }

class Point {
  has UInt ($.x, $.y, $.z, $.t);
  multi method new(UInt:D $x, UInt $y) {
    import FiniteFieldArithmetics;
    die "point ($x, $y) is not on the curve" unless
      a*$x*$x + $y*$y == 1 + d*$x*$x*$y*$y;
    self.bless: :$x, :$y, :z(1), :t($x*$y);
  }
  multi method new(Int:U $, UInt $y) {
    import FiniteFieldArithmetics;
    my ($u, $v) = ($y*$y - 1, d*$y*$y + 1);
    my $x = $u*$v**3*($u*$v**7)**(-5/8);
    if $v*$x*$x == -$u  { $x = $x * 2**(-1/4) }
    if ($x > -$x) { $x = -$x }
    return samewith($x, $y);
  }
  multi method new(blob8 $b where $b == b div 8) {
    my $y = [+] (^(b-1)).map({2**$_*bit($b,$_)});
    my $x = ::?CLASS.new(Int, $y).x;
    if $x +& 1 != bit($b, b-1) { $x = p - $x }
    samewith($x, $y);
  }

  method blob {
    blob8.new:
      ($!y/$!z)
      .polymod(2 xx (b-2))
      .Array.append(($!x/$!z) +& 1)
      .reverse
      .rotor(8)
      .map(*.reduce: 2 * * + *)
      .reverse
  }
  method ACCEPTS(::?CLASS $other) { self.blob.ACCEPTS($other.blob) }

  method add(::?CLASS $other --> ::?CLASS) {
    import FiniteFieldArithmetics;
    my (\X1, \Y1, \Z1, \T1) = ($!x, $!y, $!z, $!t);
    my (\X2, \Y2, \Z2, \T2) = ($other.x, $other.y, $other.z, $other.t);
    my \A = (Y1 - X1)*(Y2 - X2);
    my \B = (Y1 + X1)*(Y2 + X2);
    my \C = T1*2*d*T2;
    my \D = Z1*2*Z2;
    my \E = B - A;
    my \F = D - C;
    my \G = D + C;
    my \H = B + A;
    my \X3 = E*F;
    my \Y3 = G*H;
    my \T3 = E*H;
    my \Z3 = F*G;
    ::?CLASS.new: :x(X3), :y(Y3), :z(Z3), :t(T3);
  }
  method double(--> ::?CLASS) {
    import FiniteFieldArithmetics;
    my (\X1, \Y1, \Z1, \T1) = ($!x, $!y, $!z, $!t);
    my \A = X1**2;
    my \B = Y1**2;
    my \C = 2*Z1**2;
    my \H = A + B;
    my \E = H - (X1 + Y1)**2;
    my \G = A - B;
    my \F = C + G;
    my \X3 = E*F;
    my \Y3 = G*H;
    my \T3 = E*H;
    my \Z3 = F*G;
    ::?CLASS.new: :x(X3), :y(Y3), :z(Z3), :t(T3);
  }

}

multi sub infix:<*>( 0, Point $ ) returns Point { Point.new: 0, 1 }
multi sub infix:<*>( 1, Point $p) returns Point { $p }
multi sub infix:<*>( 2, Point $p) returns Point { $p.double }
multi sub infix:<*>($n, Point $p) returns Point { 2*(($n div 2)*$p) + ($n mod 2)*$p }

constant B = Point.new: Int, 4/5;

constant c = 3;
constant n = 254;

multi sub infix:<+>(Point $a, Point $b) returns Point { $a.add($b) }

class Key {
  has blob8 ($.seed, $.seed-hash);
  multi method new() { samewith blob8.new: (^256).roll(32) }
  multi method new(blob8 $seed      where b div 8  )   { self.bless: :$seed }
  multi method new(blob8 $seed-hash where (2*b) div 8) { self.bless: :$seed-hash }
  method seed-hash { $!seed-hash // H $!seed }
  method Int { 
    my $s = $.seed-hash.subbuf(0, 32);
    $s[0]   +&= 0b1111_1000;
    $s[*-1] +&= 0b0111_1111;
    $s[*-1] +|= 0b0100_0000;
    return blob-to-int($s) mod L;
  }
  method point { self.Int * B }
  method ACCEPTS(::?CLASS $other) { self.point ~~ $other.point }
  proto method sign($ --> blob8) {*}
  multi method sign(Str $msg) { samewith $msg.encode }
  multi method sign(blob8 $msg) {
    my $r = blob-to-int(H($.seed-hash.subbuf(32) ~ $msg));
    my $R = ($r mod L) * B;
    my $k = blob-to-int(H($R.blob ~ self.point.blob ~ $msg));
    my $S = ($r + $k * self.Int) mod L;
    $R.blob ~ blob8.new:
      $S.polymod(2 xx (b-1))
      .reverse
      .rotor(8)
      .map({:2[@$_]})
      .reverse
      ;
  }
}

multi verify(Str $message, $signature, $public-key) {
  samewith $message.encode, $signature, $public-key
}
multi verify(blob8 $message, $signature, blob8 $public-key where b div 8) {
  samewith $message, $signature, Point.new: $public-key
}
multi verify(blob8 $message, $signature, Point $A) {
  my Point $R .= new: $signature.subbuf(0, b div 8);
  my UInt  $S = blob-to-int($signature.subbuf(b div 8));
  die "S out of range" if $S >= L;
  my UInt  $h = blob-to-int(H($R.blob ~ $A.blob ~ $message));
  die "wrong signature" unless 
    2**c * $S * B ~~ 2**c * $R + 2**c * $h*$A;
}
