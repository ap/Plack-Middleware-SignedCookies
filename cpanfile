requires 'perl', '5.010';
requires 'strict';
requires 'warnings';
requires 'parent';

requires 'Digest::SHA';
requires 'Plack::Middleware';
requires 'Plack::Util';
requires 'Plack::Util::Accessor';

on test => sub {
	requires 'HTTP::Request::Common';
	requires 'Plack::Request';
	requires 'Plack::Test';
	requires 'Test::More';
};

# vim: ft=perl
