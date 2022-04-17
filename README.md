# Ed25519
Ed25519 in [raku](http://raku.org)

## Synopsis

```raku
use Ed25519;

# create a key
# - randomly :
my Ed25519::Key $key .= new;
# - from a seed :
my blob8 $secret-seed .= new: (^256).roll: 32;
my Ed25519::Key $key .= new: $secret-seed;

# use key to sign a message
my $signature = $key.sign: "Hello world!";

# verify signature
use Test;
lives-ok { Ed25519::verify "foo", $key.sign("foo"), $key.point };
dies-ok  { Ed25519::verify "foo", $key.sign("bar"), $key.point };
```
    
   
References
----------

* [RFC 8032](http://www.rfc-editor.org/info/rfc8032)
* Chalkias, Konstantinos, et. al. ["Taming the many EdDSAs."](https://eprint.iacr.org/2020/1244.pdf) *Security Standardisation Research Conference*, Dec. 2020
