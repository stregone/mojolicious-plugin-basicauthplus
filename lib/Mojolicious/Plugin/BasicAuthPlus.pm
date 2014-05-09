package Mojolicious::Plugin::BasicAuthPlus;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::ByteStream;
use Authen::Simple::Password;
use Authen::Simple::Passwd;
use Authen::Simple::LDAP;

our $VERSION = '0.05';

sub register {
    my ( $plugin, $app ) = @_;

    $app->renderer->add_helper(
        basic_auth => sub {
            my $self = shift;

            # Sent credentials
            my $auth = $self->req->url->to_abs->userinfo || '';

            # Required credentials
            my ( $realm, $password, $username ) = $plugin->_expected_auth(@_);
            my $callback = $password if ref $password eq 'CODE';
            my $params   = $password if ref $password eq 'HASH';

            # No credentials entered
            return $plugin->_password_prompt( $self, $realm )
                if !$auth
                    and !$callback
                    and !$params;

            # Verification within callback
            return 1 if $callback and $callback->( split /:/, $auth, 2 );

            # Verified with realm => username => password syntax
            return 1 if $auth eq ( $username || '' ) . ":$password";

            # Verified via simple, passwd file, LDAP, or Active Directory.
            if ($auth) {
                if ( $params->{'username'} and $params->{'password'} ) {
                    return 1
                        if $plugin->_check_simple( $self, $auth, $params );
                }
                elsif ( $params->{'path'} ) {
                    return 1
                        if $plugin->_check_passwd( $self, $auth, $params );
                }
                elsif ( $params->{'host'} ) {
                    return 1 if $plugin->_check_ldap( $self, $auth, $params );
                }
            }

            # Not verified
            return $plugin->_password_prompt( $self, $realm );
        }
    );
}

sub _expected_auth {
    my $self  = shift;
    my $realm = shift;

    return @$realm{qw/ realm password username /} if ref $realm eq "HASH";

    # realm, pass, user || realm, pass, undef || realm, callback
    return $realm, reverse @_;
}

sub _password_prompt {
    my ( $self, $c, $realm ) = @_;

    $c->res->headers->www_authenticate("Basic realm=\"$realm\"");
    $c->res->code(401);
    $c->rendered;

    return;
}

sub _split_auth { return split ':', $_[0] }

sub _check_simple {
    my ( $self, $c, $auth, $params ) = @_;
    my ( $username, $password ) = _split_auth($auth);

    return 1
        if $username eq $params->{'username'}
            and Authen::Simple::Password->check( $password,
                $params->{'password'} );
}

sub _check_ldap {
    my ( $self, $c, $auth, $params ) = @_;
    my ( $username, $password ) = _split_auth($auth);

    return 0 unless defined $password;
    my $ldap = Authen::Simple::LDAP->new(%$params);

    return 1 if $ldap->authenticate( $username, $password );
}

sub _check_passwd {
    my ( $self, $c, $auth, $params ) = @_;
    my ( $username, $password ) = _split_auth($auth);

    $username = '' unless $username;
    $password = '' unless $password;

    my $passwd = Authen::Simple::Passwd->new(%$params);

    return 1 if $passwd->authenticate( $username, $password );
}

1;

__END__

=head1 NAME

Mojolicious::Plugin::BasicAuthPlus - Basic HTTP Auth Helper Plus

=head1 VERSION

Version 0.05

=head1 SYNOPSIS

  # Mojolicious::Lite
  plugin 'basic_auth_plus';
  
  get '/' => sub {
      my $self = shift;
  
      $self->render(text => 'ok')
        if $self->basic_auth(
          "Realm Name" => {
              username => 'username',
              password => 'password'
          }
      );
  };
  
  # Mojolicious
  $self->plugin('BasicAuthPlus');
  
  sub index {
      my $self = shift;
  
      $self->render(text => 'ok')
          if $self->basic_auth(
              "My Realm" => {
                  path => '/path/to/some/passwd/file.txt'
              }
          );
  }

=head1 DESCRIPTION

L<Mojolicious::Plugin::BasicAuthPlus> is a helper for basic HTTP
authentication that supports multiple authentication schemes, including
a callback, explicit username and password (plaintext or encrypted) without
a callback, a passwd file, LDAP, and Active Directory.

=head1 METHODS

L<Mojolicious::Plugin::BasicAuthPlus> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

    $plugin->register;

Register condition in L<Mojolicious> application.

=head2 C<basic_auth>

Configure specific auth method (see CONFIGURATION).  Returns 1 on success,
0 on failure.

=head1 CONFIGURATION

The basic_auth method takes an HTTP Basic Auth realm name that is either a
code ref for a subroutine that will do the authentication check, or a hash,
where the realm is the hash name.  When the realm represents a named hash,
the key/value pairs specify the source of user credentials and determine the
method used for authentication (e.g., passwd file, LDAP, Active Directory).

Realm names may contain whitespace.

If a username and password are defined, then other options pertaining to a
passwd file or LDAP/ActiveDirectory authentication will be ignored, because it
it assumed you intend to compare the defined username and password against
those supplied by the user.

The following options may be set in the hash:

=head2 username

Specify the username to match.

=head2 password

Specify the password to match.  The string may be plaintext or use any of the
formats noted in L<Authen::Simple::Password>.

=head2 path

The location of a password file holding user credentials.  Per
L<Authen::Simple::Passwd>, "Any standard passwd file that has records seperated
with newline and fields seperated by ":" is supported.  First field is expected
to be username and second field, plain or encrypted password.  Required."

=head2 host

The hostname or IP address of an LDAP or Active Directory server.

=head2 basedn

The base DN to use with LDAP or Active Directory.

=head2 binddn

The bind DN to use when doing an authenticated bind against LDAP or Active
Directory.

=head2 bindpw

The password to use when doing an authenticated bind to LDAP or Active
Directory.

=head2 filter

The LDAP/ActiveDirectory filter to use when searching a directory.

=head1 EXAMPLES

  # With callback
  get '/' => sub {
      my $self = shift;
  
      return $self->render(text => 'ok')
          if $self->basic_auth(
              realm => sub { return 1 if "@_" eq 'username password' }
          );
  };
  
  # With encrypted password
  get '/' => sub {
      my $self = shift;
  
      $self->render(text => 'ok')
        if $self->basic_auth(
          "Realm Name" => {
              username => 'username',
              password => 'MlQ8OC3xHPIi.'
          }
      );
  };
  
  # Passwd file authentication
  get '/' => sub {
      my $self = shift;
  
      $self->render(text => 'ok')
        if $self->basic_auth(
          "Realm Name" => {
              path => '/path/to/passwd/file.txt'
          }
      );
  };
  
  # LDAP authentication (with anonymous bind)
  get '/' => sub {
      my $self = shift;
  
      $self->render(text => 'ok')
        if $self->basic_auth(
          "Realm Name" => {
              host   => 'ldap.company.com',
              basedn => 'ou=People,dc=company,dc=com'
          }
      );
  };
  
  # Active Directory authentication (with authenticated bind)
  get '/' => sub {
      my $self = shift;
  
      $self->render(text => 'ok')
        if $self->basic_auth(
          "Realm Name" => {
              host   => 'ldap.company.com',
              basedn => 'dc=company,dc=com',
              binddn => 'ou=People,dc=company,dc=com',
              bindpw => 'secret',
              filter =>
              '(&(objectClass=organizationalPerson)(userPrincipalName=%s))'
          }
      );
  };

=head1 BUGS

Please report any bugs or feature requests to
C<bug-mojolicious-plugin-basicauthplus at rt.cpan.org>, or through the web
interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Mojolicious-Plugin-BasicAuthPlus>.  I will be notified, and then you'll automatically be notified of progress on your bug as I make changes.

=head1 DEVELOPMENT

L<http://github.com/stregone/mojolicious-plugin-basicauthplus>

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Mojolicious::Plugin::BasicAuthPlus

You can also look for information at:

=over 4 

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Mojolicious-Plugin-BasicAuthPlus>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Mojolicious-Plugin-BasicAuthPlus>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Mojolicious-Plugin-BasicAuthPlus>

item * Search CPAN

L<http://search.cpan.org/dist/Mojolicious-Plugin-BasicAuthPlus/>

=back

=head1 ACKNOWLEDGEMENTS

Based on Mojolicious::Plugin::BasicAuth, by Glen Hinkle <tempire@cpan.org>.

=head1 AUTHOR

Brad Robertson <blr@cpan.org>

=head1 CONTRIBUTORS

Jay Mortensen <jay@purplewire.com>

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicio.us>,
L<Authen::Simple::Password>, L<Authen::Simple::LDAP>, L<Authen::Simple::Passwd>

=head1 COPYRIGHT

Copyright (c) 2013-2014 by Brad Robertson.

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

