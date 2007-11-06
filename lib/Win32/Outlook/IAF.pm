package Win32::Outlook::IAF;

use warnings;
use strict;

require Exporter;
use Carp;


=head1 NAME

Win32::Outlook::IAF - Internet Account File (*.iaf) management for Outlook Express/2003.

=head1 VERSION

Version 0.01

=cut

our $VERSION='0.01';


=head1 SYNOPSIS

Allows to create POP3, IMAP and HTTP email or NNTP news account configuration 
files, that can be imported by Microsoft Outlook Express/2003 clients.

Reverse operation is possible - most fields from such files can be decoded.

    use Win32::Outlook::IAF;

    my $iaf=Win32::Outlook::IAF->new();

    my $src='MyAccount.iaf';

    local $/;
    open(INPUT,$src) or die "Can't open $src for reading: $!\n";
    binmode(INPUT);

    $iaf->read_iaf(<INPUT>);
    close(INPUT);

    # forgot your POP3 password?
    print $iaf->{POP3Password},"\n";


=head1 DESCRIPTION

=cut


our @ISA=qw(Exporter);

use constant {
	HEADER						=> "\x66\x4D\x41\x49\x00\x00\x05\x00\x01\x00\x00\x00",
	ACCOUNT_NAME				=> "\xF0\x03\x35\x12",
	ACCOUNT_ID					=> "\xF0\x03\x3D\x12",
	CONNECTION_TYPE				=> "\xE9\x03\x39\x12",
	CONNECTION_NAME				=> "\xF0\x03\x3A\x12",
	POP3_SKIP_ACCOUNT			=> "\xF5\x03\xD0\x13",
	POP3_SERVER					=> "\xF0\x03\xC4\x13",
	POP3_USER_NAME				=> "\xF0\x03\xC5\x13",
	POP3_PASSWORD				=> "\xF6\x03\xC6\x13",
	POP3_PASSWORD_PROMPT		=> "\xF5\x03\xD2\x13",
	POP3_AUTH_TYPE				=> "\xF5\x03\xC8\x13",
	POP3_PORT					=> "\xE9\x03\xC9\x13",
	POP3_SECURE_CONNECTION		=> "\xE9\x03\xCA\x13",
	POP3_TIMEOUT				=> "\xE9\x03\xCB\x13",
	SMTP_DISPLAY_NAME			=> "\xF0\x03\x30\x14",
	SMTP_ORGANIZATION_NAME		=> "\xF0\x03\x31\x14",
	SMTP_EMAIL_ADDRESS			=> "\xF0\x03\x32\x14",
	SMTP_REPLY_TO_EMAIL_ADDRESS	=> "\xF0\x03\x33\x14",
	SMTP_SERVER					=> "\xF0\x03\x28\x14",
	SMTP_USER_NAME				=> "\xF0\x03\x29\x14",
	SMTP_PASSWORD				=> "\xF6\x03\x2A\x14",
	SMTP_PASSWORD_PROMPT		=> "\xF5\x03\x38\x14",
	SMTP_AUTH_TYPE				=> "\xE9\x03\x2C\x14",
	SMTP_PORT					=> "\xE9\x03\x2D\x14",
	SMTP_SECURE_CONNECTION		=> "\xF5\x03\x2E\x14",
	SMTP_TIMEOUT				=> "\xE9\x03\x2F\x14",
	SMTP_SPLIT_MESSAGES			=> "\xF5\x03\x34\x14",
	SMTP_SPLIT_MESSAGE_SIZE		=> "\xE9\x03\x35\x14",
	LEAVE_MAIL_ON_SERVER		=> "\xF5\x03\xCC\x13",
	REMOVE_WHEN_DELETED			=> "\xF5\x03\xCD\x13",
	REMOVE_WHEN_EXPIRED			=> "\xF5\x03\xCE\x13",
	EXPIRE_DAYS					=> "\xF5\x03\xCF\x13",
	PASSWORD_SEED				=> "\x75\x18\x15\x14",
	PASSWORD_HEADER				=> "\x01\x01",
	MAX_REC_LENGTH				=> 256,
};

# don't auto-quote constant's names (don't use '=>')
my %lookup=(
	ACCOUNT_NAME				, ['AccountName',				'Z*'],
	ACCOUNT_ID					, ['AccountID',					'Z*'],
	CONNECTION_TYPE				, ['ConnectionType',			'V'],
	CONNECTION_NAME				, ['ConnectionName',			'Z*'],
	POP3_SKIP_ACCOUNT			, ['POP3SkipAccount',			'V'],
	POP3_SERVER					, ['POP3Server',				'Z*'],
	POP3_USER_NAME				, ['POP3UserName',				'Z*'],
	POP3_PASSWORD				, ['POP3Password',				'Z*',\&_iaf_password],
	POP3_PASSWORD_PROMPT		, ['POP3PasswordPrompt',		'V'],
	POP3_AUTH_TYPE				, ['POP3AuthType',				'V'],
	POP3_PORT					, ['POP3Port',					'V'],
	POP3_SECURE_CONNECTION		, ['POP3SecureConnection',		'V'],
	POP3_TIMEOUT				, ['POP3Timeout',				'V'],
	SMTP_DISPLAY_NAME			, ['SMTPDisplayName',			'Z*'],
	SMTP_ORGANIZATION_NAME		, ['SMTPOrganizationName',		'Z*'],
	SMTP_EMAIL_ADDRESS			, ['SMTPEmailAddress',			'Z*'],
	SMTP_REPLY_TO_EMAIL_ADDRESS	, ['SMTPReplyToEmailAddress',	'Z*'],
	SMTP_SERVER					, ['SMTPServer',				'Z*'],
	SMTP_USER_NAME				, ['SMTPUserName',				'Z*'],
	SMTP_PASSWORD				, ['SMTPPassword',				'Z*',\&_iaf_password],
	SMTP_PASSWORD_PROMPT		, ['SMTPPasswordPrompt',		'V'],
	SMTP_AUTH_TYPE				, ['SMTPAuthType',				'V'],
	SMTP_PORT					, ['SMTPPort',					'V'],
	SMTP_SECURE_CONNECTION		, ['SMTPSecureConnection',		'V'],
	SMTP_TIMEOUT				, ['SMTPTimeout',				'V'],
	SMTP_SPLIT_MESSAGES			, ['SMTPSplitMessages',			'V'],
	SMTP_SPLIT_MESSAGE_SIZE		, ['SMTPSplitMessageSize',		'V'],
	LEAVE_MAIL_ON_SERVER		, ['LeaveMailOnServer',			'V'],
	REMOVE_WHEN_DELETED			, ['RemoveWhenDeleted',			'V'],
	REMOVE_WHEN_EXPIRED			, ['RemoveWhenExpired',			'V'],
	EXPIRE_DAYS					, ['ExpireDays',				'V'],
);


=head2 new

=cut

sub new {
	my ($class,%args)=@_;
	my $self={};
	foreach my $v (values %lookup) {
		next unless exists $args{$v->[0]};
		$self->{$v->[0]}=$args{$v->[0]};
	}
	bless($self,$class);
	return $self;
}


=head2 read_iaf

=cut

sub read_iaf {
	my ($self,$data)=($_[0],\$_[1]);
	my $pos=0;
	my $len=length($$data);
	confess('Premature end of data while reading header') if $pos+length(HEADER)>$len;
	$pos+=length(HEADER);
	while ($pos<$len) {
		confess('Premature end of data while reading rec_id') if $pos+4>$len;
		my $rec_id=substr($$data,$pos,4);
		$pos+=4;
		confess('Premature end of data while reading rec_len') if $pos+4>$len;
		my $rec_len=unpack('V',substr($$data,$pos,4));
		$pos+=4;
		confess('Premature end of data while reading rec') if $pos+$rec_len>$len;
		confess('Excessive record length: '.$rec_len) if $rec_len>MAX_REC_LENGTH;
		my $rec=substr($$data,$pos,$rec_len);
		$pos+=$rec_len;
		next unless exists $lookup{$rec_id};
		my $v=$lookup{$rec_id};
		$rec=$v->[2]->($rec,1) if $v->[2];
		$rec=unpack($v->[1],$rec) if $v->[1];
		$self->{$v->[0]}=$rec;
	}
	return 1;
}


=head2 write_iaf

=cut

sub write_iaf {
	my ($self,$data)=($_[0],\$_[1]);
	$$data=HEADER;
	while (my($k,$v)=each %lookup) {
		next unless defined $self->{$v->[0]};
		my $rec=$self->{$v->[0]};
		$rec=pack($v->[1],$rec) if $v->[1];
		$rec=$v->[2]->($rec) if $v->[2];
		my $rec_len=pack('V',length($rec));
		$$data.="$k$rec_len$rec";
	}
	return 1;
}


=head2 _iaf_password

=cut

sub _iaf_password {
	my ($pass,$reading)=(\$_[0],$_[1]);
	my ($ret,$pos,$len)=('',0,length($$pass));
	my $seed=PASSWORD_SEED;
	my $fill;
	if ($reading) {
		confess('Premature end of data while reading password header') if $pos+length(PASSWORD_HEADER)>$len;
		$pos+=length(PASSWORD_HEADER);
		confess('Premature end of data while reading pwd_len') if $pos+4>$len;
		my $pwd_len=unpack('V',substr($$pass,$pos,4));
		$pos+=4;
		confess('Malformed password record') if $pos+$pwd_len!=$len;
	} else {
		$ret=PASSWORD_HEADER;
		$ret.=pack('V',$len);
	}
	while ($pos<$len) {
		$fill=$pos+4>$len ? $pos+4-$len : 0;
		$seed=unpack('V',("\x00" x $fill).substr($seed,$fill));
		my $d=unpack('V',("\x00" x $fill).substr($$pass,$pos,4-$fill));
		$pos+=4-$fill;
		$ret.=substr(pack('V',$d^$seed),$fill);
		$seed=pack('V',$reading ? $d^$seed : $d);
	}
	return $ret;
}


=head1 AUTHOR

Przemek Czerkas, C<< <pczerkas at gmail.com> >>


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Win32::Outlook::IAF

You can also look for information at:

=over 4


=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Win32-Outlook-IAF>


=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Win32-Outlook-IAF>


=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Win32-Outlook-IAF>


=item * Search CPAN

L<http://search.cpan.org/dist/Win32-Outlook-IAF>

=back


=head1 BUGS

Please report any bugs or feature requests to C<bug-win32-outlook-iaf at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Win32-Outlook-IAF>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 COPYRIGHT & LICENSE

Copyright 2007 Przemek Czerkas, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of Win32::Outlook::IAF
