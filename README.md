# Ed25519
Ed25519 in [raku](http://raku.org)

## Synopsis

   my blob8 $secret-seed .= new: (^256).roll: 32;
   my blob8 $message = "Hello world!".encode;

   my Ed25519::Key $key .= new: $secret-seed;
   my $signature = $key.sign: $message;
   Ed25519::verify $message, $signature, $key.point;
   
   
References
----------

* [RFC 8032](http://www.rfc-editor.org/info/rfc8032)
