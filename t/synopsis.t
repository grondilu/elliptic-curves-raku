#!/usr/bin/env raku
use Test;
plan 4;

use ed25519;

my $message = "Hello world!".encode;
my blob8 $secret-seed .= new: ^256 .roll: 32;

my ed25519::Key $key;
lives-ok { $key .= new: $secret-seed }, "key creation";

my blob8 $signature;
lives-ok { $signature = $key.sign: $message }, "signing";

lives-ok { ed25519::verify("foo", $key.sign("foo"), $key.point.blob) }, "signature verification, true match";
dies-ok  { ed25519::verify("foo", $key.sign("bar"), $key.point.blob) }, "signature verification, true mismatch";

# vi: ft=raku
