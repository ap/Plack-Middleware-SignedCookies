use 5.006; use strict; use warnings;

package Plack::Middleware::SignedCookies;

# ABSTRACT: accept only server-minted cookies

use parent 'Plack::Middleware';

use Plack::Util ();
use Plack::Util::Accessor qw( secret secure httponly );
use Digest::SHA ();

sub _hmac { y{+/}{-~}, return $_ for &Digest::SHA::hmac_sha256_base64 }

my $length = length _hmac 'something', 'something';

sub call {
	my ( $self, $env ) = ( shift, @_ );

	my $secret = $self->secret;

	local $env->{'HTTP_COOKIE'} =
		join '; ',
		grep { s/[ \t]*=[ \t]*/=/; s/[ \t]*([-~A-Za-z0-9]{$length})\z//o and $1 eq _hmac $_, $secret }
		map  { defined && /\A[ \t]*(.*[^ \t])/ ? split /[ \t]*;[ \t]*/, "$1" : () }
		$env->{'HTTP_COOKIE'};

	delete $env->{'HTTP_COOKIE'} if '' eq $env->{'HTTP_COOKIE'};

	return Plack::Util::response_cb( $self->app->( $env ), sub {
		my $do_sign;
		for ( @{ $_[0][1] } ) {
			if ( $do_sign ) {
				my $flags = s/(;.*)// ? $1 : '';
				s/\A[ \t]+//, s/[ \t]+\z//, s/[ \t]*=[ \t]*|\z/=/; # normalise
				$_ .= ' ' . _hmac( $_, $secret ) . $flags;
				$_ .= '; secure'   if $self->secure   and $flags !~ /;[ \t]* secure   [ \t]* (?![^;])/ix;
				$_ .= '; HTTPonly' if $self->httponly and $flags !~ /;[ \t]* httponly [ \t]* (?![^;])/ix;
			}
			$do_sign = defined $do_sign ? undef : 'set-cookie' eq lc;
		}
	} );
}

sub prepare_app {
	my $self = shift;
	defined $self->httponly or $self->httponly( 1 );
	defined $self->secret   or $self->secret  ( join '', map { chr int rand 256 } 1..17 );
}

1;

__END__

=pod

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

=item C<secure>

Whether to force the I<secure> flag to be set on all cookies,
which instructs the browser to only send them when using an encrypted connection.

Defaults to false. B<You should strongly consider overriding this default with a true value.>

=item C<httponly>

Whether to force the I<HttpOnly> flag to be set on all cookies,
which instructs the browser to not make them available to Javascript on the page.

B<Defaults to true.> Provide a defined false value if you wish to override this.

=back

=head1 A NOTE ON EXPIRATION

Several other modules that offer similar functionality will also handle server-side cookie expiration.
This is obviously useful for centralising all cookie policy in one place.

However, expiration is quite likely to be a concern at the application level,
if only just to tell a user that they timed out rather than just suddenly forgetting them.
Communicating server-side expiration from the middleware to the application requires a protocol.
No standard protocol exists for this purpose, so it would have to be specific to this middleware.

But middlewares are most useful when they can be added or removed without modifying the application.
(Frameworks, in contrast, require tight coupling of the application by definition,
thus making it a reasonable choice to include cookie expiration plus interface in a framework.)
Therefore, it was an explicit design choice for this middleware to omit expiration handling.

=head1 SEE ALSO

=over 4

=item *

L<RFCE<nbsp>6265, I<HTTP State Management Mechanism>, section 4.1.2.5., I<The Secure Attribute>|http://tools.ietf.org/html/rfc6265#section-4.1.2.5>

=item *

L<MSDN, I<Mitigating Cross-site Scripting With HTTP-only Cookies>|http://msdn.microsoft.com/en-us/library/ms533046.aspx>

=back

=cut
