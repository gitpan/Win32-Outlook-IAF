#!perl -T

use Test::More 'no_plan'; #tests => 1;

BEGIN {
	use_ok( 'Win32::Outlook::IAF' );
}

local $/;
my $buf;

{
	my $iaf=Win32::Outlook::IAF->new();
	isa_ok($iaf,'Win32::Outlook::IAF');

	my $src='./t/test.iaf';
	open(INPUT,"<$src") or die "Can't open $src for reading: $!\n";
	binmode(INPUT);

	ok($iaf->read_iaf(<INPUT>),'read_iaf() from file');
	close(INPUT);

	is($iaf->{AccountName},'Test Account','AccountName match');
	is($iaf->{SMTPServer},'smtp.example.com','SMTPServer match');
	is($iaf->{SMTPDisplayName},'Test User','SMTPDisplayName match');
	is($iaf->{SMTPEmailAddress},'user@example.com','SMTPEmailAddress match');
	is($iaf->{POP3Server},'pop3.example.com','POP3Server match');
	is($iaf->{POP3UserName},'username','POP3UserName match');
	is($iaf->{POP3Password},'secret','POP3Password match');

	#change password
	$iaf->{POP3Password}='mypass';

	ok($iaf->write_iaf($buf),'write_iaf()');
}

my $iaf2=Win32::Outlook::IAF->new();
ok($iaf2->read_iaf($buf),'read_iaf() from buffer');
is($iaf2->{POP3Password},'mypass','changed POP3Password match');
