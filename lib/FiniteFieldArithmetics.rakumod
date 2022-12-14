unit module FiniteFieldArithmetics;

sub m { %*ENV<MODULUS> }

multi prefix:<->(UInt $n          --> UInt) is export { callsame() mod m }
multi infix:<+> (UInt $a, UInt $b --> UInt) is export { callsame() mod m }
multi infix:<-> (UInt $a, UInt $b --> UInt) is export { callsame() mod m }
multi infix:<*> (UInt $a, UInt $b --> UInt) is export { callsame() mod m }
multi infix:<**>(UInt $a, UInt $b --> UInt) is export { expmod $a, $b, m }
multi infix:<==>(UInt $a, UInt $b)          is export { callwith $a - $b, 0 }
