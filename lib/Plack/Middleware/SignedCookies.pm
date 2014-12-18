package Plack::Middleware::SignedCookies;
use 5.010;
use strict;
use parent 'Plack::Middleware';

# ABSTRACT: accept only server-minted cookies

use Plack::Util ();
use Plack::Util::Accessor qw( secret );
use Digest::SHA ();

sub _hmac { y{+/}{-~}, return $_ for Digest::SHA::hmac_sha256_base64( @_[0,1] ) }

my $length = length _hmac 'something', 'something';

sub call {
	my $self = shift;
	my $env  = shift;

	my $secret = $self->secret
		// do { $self->secret( join '', map { chr int rand 256 } 1..17 ) };

	my $cookie =
		join '; ',
		grep { s/(.{$length})\z//o and $1 eq _hmac $_, $secret }
		split /\s*[;,]\s*/,
		$env->{'HTTP_COOKIE'} // '';

	length $cookie
		? local $env->{'HTTP_COOKIE'} = $cookie
		: delete local $env->{'HTTP_COOKIE'};

	return Plack::Util::response_cb( $self->app->( $env ), sub {
		my ( $i, $headers ) = ( 0, $_[0][1] );
		while ( $i < $#$headers ) {
			'set-cookie' eq lc $headers->[$i++]
				? $headers->[$i++] =~ s!\A\s*([^;]+?)\K\s*(?=;|\z)!_hmac $1, $secret!e
				: ++$i;
		}
	} );
}

1;

__END__

=head1 SYNOPSIS

 # in app.psgi
 use Plack::Builder;
 
 builder {
     enable 'SignedCookies', secret => 's333333333kr1t!!!!1!!';
     $app;
 };

=head1 DESCRIPTION

This middleware modifies C<Cookie> headers in the request and C<Set-Cookie> headers in the response.
It appends a HMAC digest to outgoing cookies and removes and verifies it from incoming cookies.
It rejects incoming cookies that were sent without a valid digest.

=head1 CONFIGURATION OPTIONS

=over 4

=item C<secret>

The secret to pass to the L<Digest::SHA> HMAC function.

If not provided, a random secret will be generated using PerlE<rsquo>s built-in L<rand> function.

=back

=cut
