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
my $message = "Hello world!".encode;
my $signature = $key.sign: $message;

# verify signature
Ed25519::verify $message, $signature, $key.point;
```
    
   
References
----------

* [RFC 8032](http://www.rfc-editor.org/info/rfc8032)
