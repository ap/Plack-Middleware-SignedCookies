requires 'perl', '5.006';
requires 'strict';
requires 'warnings';

requires 'Digest::SHA';
requires 'Plack::Middleware';
requires 'Plack::Util';
requires 'Plack::Util::Accessor';

on test => sub {
	requires 'HTTP::CookieJar::LWP';
	requires 'HTTP::Request::Common';
	requires 'Plack::Test';
	requires 'Test::More';
};

# vim: ft=perl
