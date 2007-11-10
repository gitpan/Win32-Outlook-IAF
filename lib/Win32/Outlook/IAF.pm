package Win32::Outlook::IAF;

use warnings;
use strict;

require Exporter;
use Carp;

use vars qw($VERSION @ISA @EXPORT $AUTOLOAD);


$VERSION='0.9';
@ISA=qw(Exporter);
@EXPORT=qw();


# export enum constants
my %const;
use constant +{%const=(
	# ConnectionType enums
	IAF_CT_IE_DEFAULT	=> 0,
	IAF_CT_DIALER		=> 1,
	IAF_CT_DIALUP		=> 2,
	IAF_CT_LAN			=> 3,
	# AuthType enums
	IAF_AT_NONE			=> 0,
	IAF_AT_SPA			=> 1,
	IAF_AT_USE_INCOMING	=> 2,
	IAF_AT_PLAIN		=> 3,
	# NNTP PostingFormat enums
	IAF_PF_USE_OPTIONS	=> 0,
	IAF_PF_PLAIN		=> 1,
	IAF_PF_HTML			=> 2,
)};
push(@EXPORT,keys %const);


use constant {
	HEADER				=> "\x66\x4D\x41\x49\x00\x00\x05\x00\x01\x00\x00\x00",
	PASSWORD_SEED		=> "\x75\x18\x15\x14",
	PASSWORD_HEADER		=> "\x01\x01",
	MAX_FIELD_LENGTH	=> 256,
};


# field value regexes
my $bool_re=qr/^[01]$/;		# boolean
my $num_re=qr/^\d+$/;		# numeric
my $regkey_re=qr/^\d*$/;	# registry key

my $iaf_ct_re=qr/[${\IAF_CT_IE_DEFAULT}-${\IAF_CT_LAN}]/;
my $iaf_at_re=qr/[${\IAF_AT_NONE}-${\IAF_AT_PLAIN}]/;
my $iaf_pf_re=qr/[012]/;

# field binary formats
my $ulong_le_fmt='V'; # an unsigned long in portable little-endian order
my $nullstr_fmt='Z*'; # a null terminated string


my %fields=(
	# name							# id			# binary format		# value regex	# callback
	'AccountName'				=>	[305464304,		$nullstr_fmt,											],
	'AccountID'					=>	[305988592,		$nullstr_fmt,		$regkey_re,							],
	'ConnectionType'			=>	[305726441,		$ulong_le_fmt,		$iaf_ct_re,							],
	'ConnectionName'			=>	[305791984,		$nullstr_fmt,											],
	'IMAPServer'				=>	[311952368,		$nullstr_fmt,											],
	'IMAPUserName'				=>	[312017904,		$nullstr_fmt,											],
	'IMAPPassword'				=>	[312083446,		$nullstr_fmt,		'',				\&_iaf_password		],
	'IMAPAuthType'				=>	[312214517,		$ulong_le_fmt,		$iaf_at_re,							],
	'IMAPPort'					=>	[312280041,		$ulong_le_fmt,		$num_re,							],
	'IMAPSecureConnection'		=>	[312345589,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool 		],
	'IMAPTimeout'				=>	[312411113,		$ulong_le_fmt,		$num_re,							],
	'IMAPRootFolder'			=>	[312476656,		$nullstr_fmt,											],
	'IMAPPolling'				=>	[312738805,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'IMAPStoreSpecialFolders'	=>	[313000949,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'IMAPSentItemsFolder'		=>	[313066480,		$nullstr_fmt,											],
	'IMAPDraftsFolder'			=>	[313197552,		$nullstr_fmt,											],
	'IMAPPasswordPrompt'		=>	[313525237,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'IMAPPollAllFolders'		=>	[313656309,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'NNTPServer'				=>	[325059568,		$nullstr_fmt,											],
	'NNTPUserName'				=>	[325125104,		$nullstr_fmt,											],
	'NNTPPassword'				=>	[325190646,		$nullstr_fmt,		'',				\&_iaf_password		],
	'NNTPAuthType'				=>	[325321717,		$ulong_le_fmt,		$iaf_at_re,							],
	'NNTPPort'					=>	[325387241,		$ulong_le_fmt,		$num_re,							],
	'NNTPSecureConnection'		=>	[325452789,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'NNTPTimeout'				=>	[325518313,		$ulong_le_fmt,		$num_re,							],
	'NNTPDisplayName'			=>	[325583856,		$nullstr_fmt,											],
	'NNTPOrganizationName'		=>	[325649392,		$nullstr_fmt,											],
	'NNTPEmailAddress'			=>	[325714928,		$nullstr_fmt,											],
	'NNTPReplyToEmailAddress'	=>	[325780464,		$nullstr_fmt,											],
	'NNTPSplitMessages'			=>	[325846005,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'NNTPSplitMessageSize'		=>	[325911529,		$ulong_le_fmt,		$num_re,							],
	'NNTPUseGroupDescriptions'	=>	[325977077,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'NNTPPolling'				=>	[326108149,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'NNTPPostingFormat'			=>	[326173673,		$ulong_le_fmt,		$iaf_pf_re,							],
	'NNTPSignature'				=>	[326239216,		$nullstr_fmt,		$regkey_re,							],
	'NNTPPasswordPrompt'		=>	[326304757,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'POP3Server'				=>	[331613168,		$nullstr_fmt,											],
	'POP3UserName'				=>	[331678704,		$nullstr_fmt,											],
	'POP3Password'				=>	[331744246,		$nullstr_fmt,		'',				\&_iaf_password		],
	'POP3AuthType'				=>	[331875317,		$ulong_le_fmt,		$iaf_at_re,							],
	'POP3Port'					=>	[331940841,		$ulong_le_fmt,		$num_re,							],
	'POP3SecureConnection'		=>	[332006377,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'POP3Timeout'				=>	[332071913,		$ulong_le_fmt,		$num_re,							],
	'POP3LeaveMailOnServer'		=>	[332137461,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'POP3RemoveWhenDeleted'		=>	[332202997,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'POP3RemoveWhenExpired'		=>	[332268533,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'POP3ExpireDays'			=>	[332334069,		$ulong_le_fmt,		$num_re,							],
	'POP3SkipAccount'			=>	[332399605,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'POP3PasswordPrompt'		=>	[332530677,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'SMTPServer'				=>	[338166768,		$nullstr_fmt,											],
	'SMTPUserName'				=>	[338232304,		$nullstr_fmt,											],
	'SMTPPassword'				=>	[338297846,		$nullstr_fmt,		'',				\&_iaf_password		],
	'SMTPAuthType'				=>	[338428905,		$ulong_le_fmt,		$iaf_at_re,							],
	'SMTPPort'					=>	[338494441,		$ulong_le_fmt,		$num_re,							],
	'SMTPSecureConnection'		=>	[338559989,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'SMTPTimeout'				=>	[338625513,		$ulong_le_fmt,		$num_re,							],
	'SMTPDisplayName'			=>	[338691056,		$nullstr_fmt,											],
	'SMTPOrganizationName'		=>	[338756592,		$nullstr_fmt,											],
	'SMTPEmailAddress'			=>	[338822128,		$nullstr_fmt,											],
	'SMTPReplyToEmailAddress'	=>	[338887664,		$nullstr_fmt,											],
	'SMTPSplitMessages'			=>	[338953205,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
	'SMTPSplitMessageSize'		=>	[339018729,		$ulong_le_fmt,		$num_re,							],
	'SMTPSignature'				=>	[339149808,		$nullstr_fmt,		$regkey_re,							],
	'SMTPPasswordPrompt'		=>	[339215349,		$ulong_le_fmt,		$bool_re,		\&_iaf_bool			],
);


sub new {
	my ($class,%args)=@_;
	my $self={};
	while (my ($field_name,$field_def)=each %fields) {
		next unless exists $args{$field_name};
		my $field=delete $args{$field_name};
		$field=$field_def->[3]->($field,'set','') if $field_def->[3]; # call callback() as 'set'
		_check_field($field_name,$field);
		$self->{"_$field_name"}=$field;
	}
	confess('Unknown argument: '.(keys %args)[0]) if scalar keys %args;
	bless($self,$class);
	return $self;
}


sub AUTOLOAD {
	my ($self,$field)=($_[0],\$_[1]);
	confess('Not an object!') unless ref $self;
	my $field_name;
	($field_name=$AUTOLOAD)=~s/^.*:://; # trim package name
	return if $field_name eq 'DESTROY'; # Let Destroy fall through
	confess("Can't access '$field_name' field in $self") unless exists $fields{$field_name};
	my $field_def=$fields{$field_name};
	my $new_field;
	if (defined $$field) {
		$new_field=$$field;
		$new_field=$field_def->[3]->($new_field,'set','') if $field_def->[3]; # call callback() as 'set'
		_check_field($field_name,$new_field);
		$self->{"_$field_name"}=$new_field;
	} else {
		$new_field=$self->{"_$field_name"};
		$new_field=$field_def->[3]->($new_field,'get','') if $field_def->[3]; # call callback() as 'get'
	}
	return $new_field;
}


# build a reverse hash for read/write operations
my %lookup=map {
	my $field_def=$fields{$_};
	# id				# name		# binary format		# value regex			# callback
	$field_def->[0],	[$_,		$field_def->[1],	$field_def->[2] || '',	$field_def->[3] || '']
} keys %fields;


sub read_iaf {
	my ($self,$data)=($_[0],\$_[1]);
	my $pos=0;
	my $len=length($$data);
	confess('Premature end of data while reading header') if $pos+length(HEADER)>$len;
	$pos+=length(HEADER); # read header
	# read fields
	while ($pos<$len) {
		confess('Premature end of data while reading field_id') if $pos+4>$len;
		my $field_id=unpack('V',substr($$data,$pos,4));
		$pos+=4;
		confess('Premature end of data while reading field_len') if $pos+4>$len;
		my $field_len=unpack('V',substr($$data,$pos,4));
		$pos+=4;
		confess('Premature end of data while reading field') if $pos+$field_len>$len;
		confess('Excessive field length: '.$field_len) if $field_len>MAX_FIELD_LENGTH;
		my $field=substr($$data,$pos,$field_len);
		$pos+=$field_len;
		next unless exists $lookup{$field_id};
#		unless (exists $lookup{$field_id}) {
#			printf "%.8X => %d\n",unpack('N',$field_id),unpack('V',$field);
#			printf "%.8X => %s\n",unpack('N',$field_id),$field;
#			next;
#		}
		my $field_def=$lookup{$field_id};
		$field=$field_def->[3]->($field,'read','packed') if $field_def->[3]; # call callback() as 'read packed'
		$field=unpack($field_def->[1],$field) if $field_def->[1]; # apply binary format
		$field=$field_def->[3]->($field,'read','unpacked') if $field_def->[3]; # call callback() as 'read unpacked'
		my $field_name=$field_def->[0];
		_check_field($field_name,$field);
		$self->{"_$field_name"}=$field;
	}
	return 1;
}


sub write_iaf {
	my ($self,$data)=($_[0],\$_[1]);
	$$data=HEADER; # write header
	# write fields
	while (my ($field_id,$field_def)=each %lookup) {
		my $field_name=$field_def->[0];
		next unless exists $self->{"_$field_name"};
		my $field=$self->{"_$field_name"};
		$field=$field_def->[3]->($field,'write','unpacked') if $field_def->[3]; # call callback() as 'write unpacked'
		$field=pack($field_def->[1],$field) if $field_def->[1]; # apply binary format
		$field=$field_def->[3]->($field,'write','packed') if $field_def->[3]; # call callback() as 'write packed'
		my $field_len=pack('V',length($field));
		$field_id=pack('V',$field_id);
		$$data.="$field_id$field_len$field";
	}
	return 1;
}


sub _check_field {
	my ($field_name,$field)=($_[0],\$_[1]);
	my $field_def=$fields{$field_name};
	my $field_re=$field_def->[2] ? ref $field_def->[2] eq 'Regexp' ? $field_def->[2] : qr/$field_def->[2]/ : '';
	$$field!~$field_re && confess('Invalid field value: '.$$field) if $field_re;
}


# turn parameters into boolean 0/1 values
sub _iaf_bool {
	my ($value,$operation,$phase)=(\$_[0],$_[1],$_[2]);
	# this callback runs only during 'get' or 'set' operations
	return $$value unless $operation eq 'get' || $operation eq 'set';
	return $$value ? 1 : 0;
}


# decrypt passwords
sub _iaf_password {
	my ($password,$operation,$phase)=(\$_[0],$_[1],$_[2]);
	# this callback runs only during 'read' or 'write' operations
	return $$password unless $operation eq 'read' || $operation eq 'write';
	# this callback operates only on 'packed' data
	return $$password unless $phase eq 'packed';
	my ($ret,$pos,$len)=('',0,length($$password));
	my $seed=PASSWORD_SEED;
	my $fill;
	if ($operation eq 'read') {
		confess('Premature end of data while reading password header') if $pos+length(PASSWORD_HEADER)>$len;
		$pos+=length(PASSWORD_HEADER);
		confess('Premature end of data while reading password_len') if $pos+4>$len;
		my $password_len=unpack('V',substr($$password,$pos,4));
		$pos+=4;
		confess('Malformed password record') if $pos+$password_len!=$len;
	} else {
		$ret=PASSWORD_HEADER;
		$ret.=pack('V',$len);
	}
	while ($pos<$len) {
		$fill=$pos+4>$len ? $pos+4-$len : 0;
		$seed=unpack('V',("\x00" x $fill).substr($seed,$fill));
		my $d=unpack('V',("\x00" x $fill).substr($$password,$pos,4-$fill));
		$pos+=4-$fill;
		$ret.=substr(pack('V',$d^$seed),$fill);
		$seed=pack('V',$operation eq 'read' ? $d^$seed : $d);
	}
	return $ret;
}

1; # End of Win32::Outlook::IAF

__DATA__

=head1 NAME

Win32::Outlook::IAF - Internet Account File (*.iaf) management for Outlook Express/2003.


=head1 VERSION

Version 0.9


=head1 SYNOPSIS

    use Win32::Outlook::IAF;

    my $iaf=new Win32::Outlook::IAF;

    my $src='MyAccount.iaf';

    local $/;
    open(INPUT,$src) or die "Can't open $src for reading: $!\n";
    binmode(INPUT);

    $iaf->read_iaf(<INPUT>);
    close(INPUT);

    # forgot your POP3 password?
    print $iaf->POP3Password();

    $iaf=new Win32::Outlook::IAF(
      IMAPServer => 'imap.example.com',
      IMAPUserName => 'user@example.com',
    );

    $iaf->IMAPSecureConnection(1);     # set boolean value
    $iaf->IMAPSecureConnection('yes'); # another way

    $iaf->IMAPAuthType(IAF_AT_USE_INCOMING); # handy constants

    $iaf->IMAPPort('hundred'); # dies (not a number)

    $iaf->NonExistent(); # dies (can't access nonexistent field)


=head1 DESCRIPTION

Allows to create SMTP, POP3, IMAP and HTTP email or NNTP news account configuration 
files, that can be imported by Microsoft Outlook Express/2003 clients.

Reverse operation is possible - most fields from such files can be decoded.


=head1 General Methods

=over 4

=item new()

=item read_iaf()

=item write_iaf()

=back


=head1 Account Fields

=over 4

=item AccountName()

Account name displayed in list of accounts in Outlook or Outlook Express.

=item AccountID()

Unique ID of the account. Name of the registry key that stores the account settings.

=back


=head1 Connection Fields

=over 4

=item ConnectionType()

Connection type used by account. One of the L<IAF_CT_*|/"ConnectionType Values"> enumeration values.

=item ConnectionName()

Name of the dial-up account. This is used when ConnectionType() is set to L<IAF_CT_DIALUP|/"IAF_CT_DIALUP">.

=back


=head1 SMTP Fields

=over 4

=item SMTPServer

SMTP server host name.

=item SMTPUserName

User name used when connecting to SMTP server.

=item SMTPPassword

Password used when connecting to SMTP server.

=item SMTPAuthType

Authentication method required by SMTP server. One of the L<IAF_AT_*|"AuthType Values"> enumeration values.

=item SMTPPort

SMTP server port.

=item SMTPSecureConnection

Use secure connection (SSL) to the SMTP server.

=item SMTPTimeout

Timeout in seconds for communication with SMTP server.

=item SMTPDisplayName

Display name of the user. This is used as a name in 'From:' mail header.

=item SMTPOrganizationName

Organization of the user. This is used in 'Organization:' mail header.

=item SMTPEmailAddress

Sender email address. This is used as the email address in 'From:' mail header.

=item SMTPReplyToEmailAddress

Reply To email address. This is used as the email address in 'Reply-To:' mail header.

=item SMTPSplitMessages

=item SMTPSplitMessageSize

=item SMTPSignature

=item SMTPPasswordPrompt

=back


=head1 POP3 Fields

=over 4

=item POP3Server

POP3 server host name.

=item POP3UserName

User name used when connecting to POP3 server.

=item POP3Password

Password used when connecting to POP3 server.

=item POP3AuthType

Authentication method required by POP3 server. One of the L<IAF_AT_*|"AuthType Values"> enumeration values.

=item POP3Port

POP3 server port.

=item POP3SecureConnection

Use secure connection (SSL) to the POP3 server.

=item POP3Timeout

Timeout in seconds for communication with POP3 server.

=item POP3LeaveMailOnServer

=item POP3RemoveWhenDeleted

=item POP3RemoveWhenExpired

=item POP3ExpireDays

=item POP3SkipAccount

=item POP3PasswordPrompt

=back


=head1 IMAP Fields

=over 4

=item IMAPServer()

IMAP server host name.

=item IMAPUserName()

User name used when connecting to IMAP server.

=item IMAPPassword()

Password used when connecting to IMAP server.

=item IMAPAuthType()

Authentication method required by IMAP server. One of the L<IAF_AT_*|"AuthType Values"> enumeration values.

=item IMAPPort()

IMAP server port.

=item IMAPSecureConnection()

Use secure connection (SSL) to the IMAP server.

=item IMAPTimeout()

Timeout in seconds for communication with IMAP server.

=item IMAPRootFolder()

Root folder path on IMAP server.

=item IMAPPolling()

Include this account when receiving mail or synchronizing.

=item IMAPStoreSpecialFolders()

Store special folders on IMAP server.

=item IMAPSentItemsFolder()

Send Items folder path on IMAP server.

=item IMAPDraftsFolder()

Drafts folder path on IMAP server.

=item IMAPPasswordPrompt()

Prompt for password when connecting to IMAP server.

=item IMAPPollAllFolders

=back


=head1 NNTP Fields

=over 4

=item NNTPServer

NNTP server host name.

=item NNTPUserName

User name used when connecting to NNTP server.

=item NNTPPassword

Password used when connecting to NNTP server.

=item NNTPAuthType

Authentication method required by NNTP server. One of the L<IAF_AT_*|"AuthType Values"> enumeration values.

=item NNTPPort

NNTP server port.

=item NNTPSecureConnection

Use secure connection (SSL) to the NNTP server.

=item NNTPTimeout

Timeout in seconds for communication with NNTP server.

=item NNTPDisplayName

Display name of the user. This is used as a name in 'From:' message header.

=item NNTPOrganizationName

Organization of the user. This is used in 'Organization:' message header.

=item NNTPEmailAddress

Sender email address. This is used as the email address in 'From:' message header.

=item NNTPReplyToEmailAddress

Reply To email address. This is used as the email address in 'Reply-To:' message header.

=item NNTPSplitMessages

=item NNTPSplitMessageSize

=item NNTPUseGroupDescriptions

=item NNTPPolling

=item NNTPPostingFormat

=item NNTPSignature

=item NNTPPasswordPrompt

=back


=head1 Enumeration Values

=head2 ConnectionType Values

=over 4

=item IAF_CT_IE_DEFAULT

Use IE connection setting.

=item IAF_CT_DIALER

Connect using 3rd party dialer.

=item IAF_CT_DIALUP

Connect using dial-up account.

=item IAF_CT_LAN

Connect using local network.

=back


=head2 AuthType Values

=over 4

=item IAF_AT_NONE

SMTP server does not require authentication.

=item IAF_AT_SPA

Logon to SMTP server using name and secure password authentication.

=item IAF_AT_USE_INCOMING

Logon to SMTP server using incoming mail server settings.

=item IAF_AT_PLAIN

Logon to SMTP server using name and plaintext password.

=back


=head2 PostingFormat Values

=over 4

=item IAF_PF_USE_OPTIONS

...

=item IAF_PF_PLAIN

...

=item IAF_PF_HTML

...

=back


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
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Win32-Outlook-IAF>.
I will be notified, and then you'll automatically be notified of progress on your bug as I make changes.


=head1 COPYRIGHT & LICENSE

Copyright 2007 Przemek Czerkas, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.
