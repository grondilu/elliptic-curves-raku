#!/usr/bin/env raku
use Test;
plan 3;

use Ed25519;

my $message = "Hello world!".encode;
my blob8 $secret-seed .= new: (^256).roll: 32;

my Ed25519::Key $key;
lives-ok { $key .= new: $secret-seed }, "key creation";

my blob8 $signature;
lives-ok { $signature = $key.sign: $message }, "signing";

lives-ok { Ed25519::verify($message, $signature, $key.point.blob) }, "signature verification";

# vi: ft=raku
