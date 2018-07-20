#!perl -T

eval { require Test::Kwalitee };
exit if $@;
Test::Kwalitee->import();
