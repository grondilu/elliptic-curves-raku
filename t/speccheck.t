#!/usr/bin/env raku
use Test;

use ed25519;
use JSON::Tiny;

sub to-blob(Str $hex where /^ <xdigit>* $/) {
  blob8.new: $hex.comb(/../)».parse-base(16)
}
my @cases = |from-json slurp 't/cases.json';
plan @cases.elems;

for @cases {
  if $++ !== 6|7|9 {
    lives-ok {
      ed25519::verify
      to-blob(.<message>),
      to-blob(.<signature>),
      to-blob(.<pub_key>)
    }, "...{.<message>.substr(*-4)}"
  } else { skip 'problematic case' }
}

# vi: ft=raku

