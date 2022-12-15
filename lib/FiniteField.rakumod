unit module FiniteField;

our $*modulus is export;

multi postfix:<⁻¹>(UInt $a) returns UInt is export {
  expmod $a, $*modulus - 2, $*modulus
}
multi infix:</>(Int $a, UInt $b) returns UInt is export { $a*$b⁻¹ mod $*modulus }

multi prefix:<->(UInt $n          --> UInt) is export { callsame() mod $*modulus }
multi infix:<+> (UInt $a, UInt $b --> UInt) is export { callsame() mod $*modulus }
multi infix:<-> (UInt $a, UInt $b --> UInt) is export { callsame() mod $*modulus }
multi infix:<*> (UInt $a, UInt $b --> UInt) is export { callsame() mod $*modulus }
multi infix:<**>(UInt $a, UInt $b --> UInt) is export { expmod $a, $b, $*modulus }
multi infix:<==>(UInt $a, UInt $b)          is export { callwith $a - $b, 0 }
