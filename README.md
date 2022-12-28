[![SparrowCI](https://ci.sparrowhub.io/project/gh-grondilu-elliptic-curves-raku/badge)](https://ci.sparrowhub.io)

# Elliptic Curves Cryptography in raku

secp256k1 and ed25519 in [raku](http://raku.org)

## Synopsis

```raku
{
    use secp256k1;

    say G;
    say $_*G for 1..10;

    use Test;
    is 35*G + 5*G, 40*G;
}

{
    use ed25519;

    # create a key
    # - randomly :
    my ed25519::Key $key .= new;
    # - from a seed :
    my blob8 $secret-seed .= new: ^256 .roll: 32;
    my ed25519::Key $key .= new: $secret-seed;

    # use key to sign a message
    my $signature = $key.sign: "Hello world!";

    # verify signature
    use Test;
    lives-ok { ed25519::verify "foo", $key.sign("foo"), $key.point };
    dies-ok  { ed25519::verify "foo", $key.sign("bar"), $key.point };
}
```
    
   
References
----------

* [RFC 8032](http://www.rfc-editor.org/info/rfc8032)
* Jacobian coordinates:
  - [WikiBooks entry](https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates)
  - [hyperelliptic.org page](http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html)
* Chalkias, Konstantinos, et. al. ["Taming the many EdDSAs."](https://eprint.iacr.org/2020/1244.pdf) *Security Standardisation Research Conference*, Dec. 2020
