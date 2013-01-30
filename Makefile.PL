use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Mojolicious::Plugin::BasicAuthPlus',
    AUTHOR              => q{Brad Robertson <blr@cpan.org>},
    VERSION_FROM        => 'lib/Mojolicious/Plugin/BasicAuthPlus.pm',
    ABSTRACT_FROM       => 'lib/Mojolicious/Plugin/BasicAuthPlus.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Mojolicious' => '1.4',
        'Authen::Simple::Password' => 0,
        'Authen::Simple::Passwd' => 0,
        'Authen::Simple::LDAP' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Mojolicious-Plugin-BasicAuthPlus-*' },
);
