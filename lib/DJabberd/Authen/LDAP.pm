package DJabberd::Authen::LDAP;

use warnings;
use strict;
use base 'DJabberd::Authen';

use DJabberd::Log;
our $logger = DJabberd::Log->get_logger;
use Net::LDAP;

sub log {
    $logger;
}

=head1 NAME

DJabberd::Authen::LDAP - An LDAP authentication module for DJabberd

=head1 VERSION

Version 0.01
=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

    <VHost mydomain.com>

        [...]

        <Plugin DJabberd::Authen::LDAP>
            LDAPURI		ldap://localhost/
            LDAPBindDN		cn=reader
            LDAPBindPW		pass
            LDAPBaseDN		ou=people
            LDAPFilter		(&(inetAuthorizedServices=jabber)(uid=%u))
            LDAPMethod		rebind
        </Plugin>
    </VHost>

LDAPURI , LDAPBaseDN, and LDAPFilter are required
Everything else is optional.

The Only LDAPMethod supported at the moment is rebind which performs a bind as LDAPBindDN
 or does anonymous bind, then searches for the user using LDAPFilter and then will rebind
 as the found DN to verify the password.

LDAPFilter is an LDAP filter with a %u that will be substituted with the incoming userid

=head1 AUTHOR

Edward Rudd, C<< <urkle at outoforder.cc> >>

=cut

sub set_config_ldapuri {
    my ($self, $ldapuri) = @_;
    if ( $ldapuri =~ /((?:ldap[si]?\:\/\/)?[\w\.%\d]+\/?)/ ) {
        $self->{'ldap_uri'} = $ldapuri;
    }
}

sub set_config_ldapbinddn {
    my ($self, $ldapbinddn) = @_;
    $self->{'ldap_binddn'} = $ldapbinddn;
}

sub set_config_ldapbindpw {
    my ($self, $ldapbindpw) = @_;
    $self->{'ldap_bindpw'} = $ldapbindpw;
}

sub set_config_ldapbasedn {
    my ($self, $ldapbasedn) = @_;
    $self->{'ldap_basedn'} = $ldapbasedn;
}

sub set_config_ldapfilter {
    my ($self, $ldapfilter) = @_;
    $self->{'ldap_filter'} = $ldapfilter;
}

sub set_config_ldapmethod {
    my ($self, $ldapmethod) = @_;
    if ( $ldapmethod =~ /^(?:rebind)$/ ) {
        $self->{'ldap_method'} = $ldapmethod;
    } else {
	$self->{'ldap_method'} = 'unknown';
    }
}

sub finalize {
    my $self = shift;
    $logger->error_die("Invalid LDAP URI") unless $self->{ldap_uri};
    $logger->error_die("No LDAP BaseDN Specified") unless $self->{ldap_basedn};
    if (not defined $self->{'ldap_method'}) { $self->{'ldap_type'} = 'rebind'; }
    for ($self->{ldap_type}) {
	if (/^rebind$/) {
	    # check additional required params
	    $logger->error_die("Must specify filter with userid as %u") unless $self->{ldap_filter};
	} else {
	    $logger->error_die("Invalid LDAP Authentication Method");
	}
    }
    # Initialize ldap connection
    $self->{'ldap_conn'} = Net::LDAP->new($self->{ldap_uri})
	or $logger->error_die("Could not connect to LDAP Server ".$self->{ldap_uri});
}

sub can_retrieve_cleartext { 0 }

sub check_cleartext {
    my ($self, $cb, %args) = @_;
    my $username = $args{username};
    my $password = $args{password};
    my $conn = $args{conn};
    unless ($username =~ /^\w+$/) {
        $cb->reject;
        return;
    }

    my $ldap = $self->{'ldap_conn'};

    if (defined $self->{'ldap_binddn'}) {
        if (not $ldap->bind($self->{'ldap_binddn'},
    		password=>$self->{'ldap_bindpw'})) {
    	    $logger->info("Could not bind to ldap server");
    	    $cb->decline;
    	}
    } else {
	$ldap->unbind;
    }
    
    my $filter = $self->{'ldap_filter'};
    $filter =~ s/%u/$username/;
    $logger->info("Searching $filter on ".$self->{'ldap_basedn'});
    my $srch = $ldap->search(
	base=>$self->{'ldap_basedn'},
	filter=>$filter,
	attrs=>['dn']);
    if ($srch->code || $srch->count != 1) {
	$logger->info("Account $username not found.");
	$cb->decline;
    } else {
        my $entry = $srch->entry(0);
        my $DN = $entry->dn();
        undef($entry);
        undef($srch);
    
        my $res = $ldap->bind($DN,password=>$password);

        if ($res->code == 0) {
    	    $cb->accept;
        } else {
	    $cb->reject;
        }
    }
}

=head1 COPYRIGHT & LICENSE

Original work Copyright 2006 Alexander Karelas, Martin Atkins, Brad Fitzpatrick and Aleksandar Milanov. All rights reserved.
Copyright 2007 Edward Rudd. All rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
