#!/usr/bin/perl -w
#
# Morgan Jones (morgan@morganjones.org)
# $Id$
#
# all customization is done in the .cf file indicated by -c argument.
# Use convert_ldap.cf as a template.
#
# Description: general purpose script to convert an ldif from one ldap
# server/schema to another.  you can omit entire entries, transform
# DNs, omit/modify/change attributes, attribute values and
# objectclasses.
#
# The intended use is to convert the entire contents of a legacy
# directory into a newly configured directory.
#
# Usage:
# Dump the contents of the newly configured directory (Centos DS in this case):
#     /usr/lib64/dirsrv/slapd-<instance>/db2ldif -s <base> -a /var/tmp/base.ldif
#     or ODSEE: dsconf export --no-repl -h localhost -p port <base> /var/tmp/base.ldif
# Transform the output of the old directory with this script:
#     cat <old_base>_110511.20.49.38.ldif |./convert_ldap.pl > converted.ldif
# Concatenate the converted old directory to the dump of the new directory.  This
#     does assume that your containers were removed by convert_ldap.pl.
#     cat /var/tmp/base.ldif converted.ldif > /var/tmp/o_msues.ldif
# Stop slapd:
#     /usr/lib64/dirsrv/slapd-<instance>/stop-slapd
# Import the new data:
#     /usr/lib64/dirsrv/slapd-<instance>/ldif2db -s <base> -i /var/tmp/<base>.ldif
# It is normal to get a ton of errors the first few times.  If so, modify 
#     convert_ldap.cf or base.ldif and repeat above.
# 
use strict;
use Getopt::Std;
use Data::Dumper;

sub contains_required_object_classes(@);
sub attr_contains_desired_objectclass($);
sub print_usage();
sub remove_commas(@);
sub remove_leading_trailing_space(@);
sub modify_cn(@);
sub get_ntuserdomainid(@);
sub merge_csv_changes(@);

my %opts;
getopts('dc:s', \%opts);

$opts{c} || print_usage();
$opts{h} && print_usage();

require $opts{c};

my @working_dir =  split (/\//, $0);
pop @working_dir;
my $working_dir = join '/', @working_dir;
$working_dir .= "/";

my %dns_changed;

our %base_change;
our @bases_to_ignore;
our @desired_objectclasses;
our @required_objectclasses;
our @skip_objectclasses;
our %attr_change;
our %changes;
our $add_to_top;
our $free_form_LDIF;
our %modify_value;
our $convert_base64;

# remove spaces before/after commas to make comparisons reliable
for (@bases_to_ignore) { s/\s*,\s*/,/g; }

%changes = merge_csv_changes(%changes);

$/="";  # Pull in a full LDAP entry on each pass of the while loop.

# save ldif in a list to post-process for dn updates
my @entries;
my $add_to_top_printed = 0;

while(<>) {
    # Create a single line out of LDIF continued lines.
    s/\n\s+//g;

    my @l = split /\n/;

    my $skip = 0;
    for my $oc (@skip_objectclasses) {
	$skip = 1 if (grep /^objectclass:\s*$oc/i, @l);
    }
    next if $skip;

    my $dn;
    # skip contents above the dn (# get rid of version: 1 and #entry-id: num)
    do {
        $dn = shift @l;
    } until ($#l<0 || $dn =~ /^dn:/);

    # comments are sometimes set out alone in LDIF--the above strips
    # them leaving nothing so we skip those empty records.
    next if ($#l<0);

    my $orig_dn = $dn;
    
    # remove spaces before and/or after commas
    $dn =~ s/\s*,\s*/,/g;

    for my $k (keys %base_change) {
	my $t = ref $base_change{$k};

	my $ou;
	if ($t eq "CODE") {
	    $ou = $base_change{$k}->(@l);
	} else {
	    $ou = $base_change{$k};
	}
	$dn =~ s/$k/$ou/i;

	if ($dn ne $orig_dn) {
	    my $hash_dn = lc $orig_dn;
	    $hash_dn =~ s/^dn:\s*//;
	    $dns_changed{$hash_dn} = $dn;
	    $dns_changed{$hash_dn} =~ s/^dn:\s*//;

	    # we've changed the top level entry or rdn and we have to update the rdn to match.
	    my $rdn = $dns_changed{$hash_dn};
	    $rdn = (split /\,/, $rdn)[0];
	    $rdn =~ s/=/: /;
	    my $rdn_attr = (split /\s+/, $rdn)[0];
	    if (grep /^$rdn_attr/i, @l) {
		for (@l) {
		    s/^$rdn_attr/:/i;
		}
		push @l, $rdn;
	    }
	}
    }



    my $skip_base = 0;
    for my $b (@bases_to_ignore) { 
	$skip_base=1 if ($dn =~ /$b\s*$/i); 
    }
    next if ($skip_base);

    # skip entire entries unless they're in our list of required objectclasses.
    next unless contains_required_object_classes(@l);

    map {
	if ($convert_base64 && /::/) {
	    my ($lhs,$rhs) = split /::/;
	    $rhs = `echo $rhs | openssl base64 -d`;
	    $_ = ${lhs}. ": " . $rhs;
	}

    	# we strip entries and objectclasses by removing the name
    	# here.  Perl arrays are immutable so a new array must be
    	# created (below) to actually strip entries.  We mark them for
    	# later removal by replacing the contents with ":"

	if (/^objectclass:/i && !attr_contains_desired_objectclass($_)) {
	    s/^objectclass:/:/i 
	}

	for my $attr (keys %modify_value) {
	    $modify_value{$attr}->(\$_)
	      if (/$attr:/i);
	}

	# change attribute values
    	for my $k (keys %attr_change) {
	    if ($attr_change{$k} =~ '%%remove_if_empty%%') {
		$_ = ":"
		  if ($_ =~ /:\s*$/);
	    } else {
		s/$k:/$attr_change{$k}:/i;
	    }
    	}
    } @l;



    for my $objectclass (sort keys %changes) {
	# only make changes if the entry has the intended objectclass
	next unless (grep /^objectClass:\s*$objectclass/i, @l);
	
	map {
	    for my $oc (keys %{$changes{$objectclass}{objectclass_name_change}}) {

		my $t = ref $changes{$objectclass}{objectclass_name_change}{$oc};

		my $new_oc;
		if ($t eq "CODE") {
		    $new_oc = $changes{$objectclass}{objectclass_name_change}{$oc}->(@l);
		} else {
		    $new_oc = $changes{$objectclass}{objectclass_name_change}{$oc};
		}
		s/(objectclass:)\s*$oc/$1 $new_oc/i;
	    }

	    # change attributes.  It's normal for attributes to end up /^:/--see note above.
	    for my $k (keys %{$changes{$objectclass}{attr_change}}) {
	    	s/^$k:/$changes{$objectclass}{attr_change}{$k}:/i
	    }
	      
	} @l;

	# change attribute values
	for my $k (keys %{$changes{$objectclass}{attr_set_value}}) {
	    unless (grep /^$k:.*/i, @l) {
		if (my $t = ref $changes{$objectclass}{attr_set_value}{$k}) {
		    if ($t eq "CODE") {
			push @l, $k . ": " . $changes{$objectclass}{attr_set_value}{$k}->(@l)
		    } else {
			die "reference of type $t in \$changes{$objectclass}{attr_setup_value}{$k} is not valid!";
		    }
		} else {
		    push @l, $k. ": ". $changes{$objectclass}{attr_set_value}{$k}
		}
	    }
	}

	if (exists $changes{$objectclass}{change_rdn} && $changes{$objectclass}{change_rdn}) {
	    my ($change_to) = grep /$changes{$objectclass}{change_rdn}\s*:.*/i, @l;
	    if (defined $change_to) {
		$change_to =~ s/:\s*/=/;
		my $new_dn = $dn;
		$new_dn =~ s/dn:\s*[^\,]+(\,.*)/dn: $change_to$1/;

		my $hash_dn = lc $orig_dn;
		$hash_dn =~ s/^dn:\s*//;
		$dns_changed{$hash_dn} = $new_dn;
		$dns_changed{$hash_dn} =~ s/^dn:\s*//;

		$dn = $new_dn;
	    }
	}

	for my $oc (@{$changes{$objectclass}{add_objectclasses}}) {
	    push @l, "objectclass: " . $oc
	      if (!grep /objectclass:\s*$oc/i, @l);
	}

	for my $merge_file (keys %{$changes{$objectclass}{merge_from_csv}}) {
	    my $unique_id_index=0;
	    for (@{$changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}}) {
		last if (lc $changes{$objectclass}{merge_from_csv}{$merge_file}{unique_identifier} eq lc $_);
		$unique_id_index++;
	    }

	    my $unique_id = $changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}[$unique_id_index];
	
	    # walk the saved merges and apply them to the entry if they're found.
	    for my $unique_id_value (keys %{$changes{$objectclass}{merge_from_csv}{$merge_file}{values}}) {
		if (grep /$unique_id:\s*$unique_id_value/i, @l) {
		    for my $change_attr (keys %{$changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$unique_id_value}}) {
			if (grep /$change_attr:\s*/i, @l) {
			    if (lc $change_attr eq "objectclass") {
				if (!grep /objectclass:\s*$changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$unique_id_value}{$change_attr}/i, @l) {
				    print STDERR "adding objectclass: $changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$unique_id_value}{$change_attr}\n"
				      if (exists($opts{d}));
				    push @l, "objectclass: " . $changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$unique_id_value}{$change_attr}
				}
			    } else {
				print STDERR "comparing from csv : ", $change_attr, ": ", 
				  $changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$unique_id_value}{$change_attr}, "\n"
				    if (exists($opts{d}));
				map { 
				    s/$change_attr:.*/$change_attr: $changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$unique_id_value}{$change_attr}/;
				} @l;
			    }
			} else {
			    # the attribute doesn't yet exist in the entry:
			    print STDERR "adding from csv: ", $change_attr, ": ", 
			      $changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$unique_id_value}{$change_attr}, "\n"
				if (exists $opts{d});
			
			    push @l, $change_attr . ": " . 
			      $changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$unique_id_value}{$change_attr};
			}
		    }

		    if (exists $changes{$objectclass}{merge_from_csv}{$merge_file}{objectclass_name_change}) {

			for my $oc (keys %{$changes{$objectclass}{merge_from_csv}{$merge_file}{objectclass_name_change}}) {
			    map {
				s/(objectclass:)\s*$oc/$1 $changes{$objectclass}{merge_from_csv}{$merge_file}{objectclass_name_change}{$oc}/i;
			    } @l;
			}
		    }
		}
	    }
	}
    }

    push @entries, [ lc $dn, @l ];

    if (((!$add_to_top_printed) && ($add_to_top !~ /^\s*$/)) && !$opts{s}) {
	print $add_to_top . "\n";
	$add_to_top_printed = 1;
    }
}

for (@entries) {
    for (@{$_}) {
	my $new_member;

	my $attr;
	my $entry;
	if (/^(uniqueMember):\s*(.*)/i || /^(memberUid):\s*(.*)/i ||
	    /^(modifiersName):\s*(.*)/i || /^(creatorsName):\s*(.*)/i ||
	   /^(member):\s*(.*)/i) {
	    $attr = $1;
	    my $dn_from_member = lc $2;
	    $dn_from_member =~ s/\s*,\s*/,/g;

	    $new_member = $dns_changed{$dn_from_member}
	      if (exists $dns_changed{$dn_from_member});

	    $entry = $attr . ": " . $new_member
	      if (defined $new_member);
	} else {
	    $entry = $_;
	}

	print "$entry\n" unless (!defined $entry || $entry =~ /^:/);
    }
    print "\n";

    if (((!$add_to_top_printed) && ($add_to_top !~ /^\s*$/)) && !$opts{s}) {
	print $add_to_top . "\n";
	$add_to_top_printed = 1;
    }
 }



print $free_form_LDIF . "\n"
  unless exists ($opts{s});



# Subroutines
######
sub contains_required_object_classes(@) {
    my @e = @_;
    
    for my $oc (@required_objectclasses) {
        return 1 if (grep /objectclass:\s*$oc/i, @e);
    }
    return 0;
}

######
sub attr_contains_desired_objectclass($) {
    my $e = shift;

    my $oc = (split/:\s*/, $e)[1];

    for my $doc (@desired_objectclasses) {
        if (lc $oc eq lc $doc) {
            return 1;
        }
    }

    return 0;
}


######
sub print_usage() {
    print "usage: cat orig.ldif | $0 [-s] -c <config file> > new.ldif\n";
    print "\t-c <config file> configuration file\n";
    print "\t-s read input from stdin.  Doesn't add top or bottom entries.\n";
    print "\n";
    exit;
}


sub modify_cn(@) {
    my $s = shift;

    remove_commas($s);
    remove_leading_trailing_space($s);
}

sub remove_commas(@) {
    my $s = shift;

    $$s =~ s/\,//g;
}

sub remove_leading_trailing_space(@) {
    my $s = shift;

    my ($lhs,$rhs) = split /:\s*/;

    $rhs =~  s/^\s+//g;
    $rhs =~  s/\s+$//g;

    $$s = $lhs . ": " . $rhs;
}

sub get_ntuserdomainid(@) {
    my @e = @_;

    for (@e) {
	if (/uid:\s*(.*)/) {
	    return "ntuserdomainid: $1";

	}
    }

    die "uid is not found in the passed entry!";
}


sub merge_csv_changes(@) {
    my %changes = @_;

    for my $objectclass (sort keys %changes) {
	# walk through the changes to merge in from csv files and save them in the %changes hash for use later
	if (exists $changes{$objectclass}{merge_from_csv}) {
	    for my $merge_file (keys %{$changes{$objectclass}{merge_from_csv}}) {
		print STDERR "\nworking on merge file $merge_file..\n"
		  if (exists $opts{d});

		# open file based on hash key under $changes->{merge_from_csv}
		open (IN, $working_dir . $merge_file . ".csv") || die "can't open merge_from_csv file $merge_file..";

		# skip the header if so configured
		<IN> if ($changes{$objectclass}{merge_from_csv}{$merge_file}{header} eq "yes"); 

		# find the index of the unique id so it can be used as a hash key
		my $unique_id_index=0;
		for (@{$changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}}) {
		    last if (lc $changes{$objectclass}{merge_from_csv}{$merge_file}{unique_identifier} eq lc $_);
		    $unique_id_index++;
		}

		while (<IN>) {
		    chomp;

		    my @csv_line = split /,/;

		    # handle fields that count off into infinity in spreadsheet.
		    my $field_count=0;
		    for (@csv_line) {
			$field_count++ unless /^\s*$/;
		    }
		    next if $field_count < $changes{$objectclass}{merge_from_csv}{$merge_file}{min_num_cols};

		    print STDERR "\ncsv line: /", join '-', @csv_line, "/\n"
		      if (exists $opts{d});

		    my $skip_entry=0;
		    my $i = 0;

		    for ($i=0; $i<=$#csv_line+1; $i++) {
			# skip if either is empty.  TODO: do we ever want to clear an attribute here?
			next unless (defined $changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}[$i]);
			next if (!defined ($csv_line[$i]) || $csv_line[$i] =~ /^\s*$/);

			# qw// has no way to enter an empty field so we use "".
			next if ($changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}[$i] eq '""');
			next if ($skip_entry);

			if ( $changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}[$i] 
			     =~ /^\s*objectclass:(.*)$/i) {
			    my $value = $1;
			    if ($csv_line[$i] =~ /^\s*y/i) {
				print STDERR "assigning objectclass: ", $value, "\n"
				  if (exists $opts{d});
				$changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$csv_line[$unique_id_index]}{objectclass} = $value;
			    }
			    next;
			}

			if ($changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}[$i] 
			    =~ /^\s*active:(.*)$/i) {
			    if ($csv_line[$i] =~ /^\s*n/i) {
				print STDERR "skipping entry, $changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}[$i]: ".
				  "$csv_line[$i]\n"
				    if (exists $opts{d});

				delete $changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$csv_line[$unique_id_index]}
				  if (exists $changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$csv_line[$unique_id_index]});

				$skip_entry=1;
			    }
			    next;
			}

			print STDERR "assigning ", $changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}[$i], " to ",
			  $csv_line[$i],"\n"
			    if (exists $opts{d});
		      
			$changes{$objectclass}{merge_from_csv}{$merge_file}{values}{$csv_line[$unique_id_index]}{
			    $changes{$objectclass}{merge_from_csv}{$merge_file}{cols_to_ldap_attrs}[$i]} = 
			      $csv_line[$i];
		    }
		}
	    }
	}
    }    

    return %changes;
}
