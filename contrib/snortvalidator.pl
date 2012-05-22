#!/usr/bin/perl

# Copyright 2009 Christian Holler (decoder@own-hero.net)
#           2010 Pablo Rincon pablo.rincon.crespo@gmail.com [Added version syntax support]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. 

use strict;
use Parse::Snort;
use Net::IP;
use Net::CIDR;
use Data::Dumper;
use Getopt::Std;
use vars qw/ %opt /;

# Command line options processing
my $opt_string = 'hildsawvqt:';
getopts( $opt_string, \%opt ) or usage();
usage() if ($opt{h});

sub usage {
    print "Usage: $0 [OPTION...] FILE [FILE...]\n";
    print "\n";
    print " Options:\n";
    print "  -a        Abort on the first error encountered\n";
    print "  -d        Debug (currently only prints the unvalidated rule structure)\n";
    print "  -h        Display this dialog\n";
    print "  -i        Do case-insensitive checking at some points to be less strict\n";
    print "  -l        Consider all rules to be local (i.e. check for valid local SID)\n";
    print "  -q        Be quiet (don't display summary)\n";
    print "  -s        Display SID additionally to file and linenumber in errors and warnings\n";
    print "  -v        Display some additional info, like what file is being processed, version syntax, etc.\n";
    print "  -t ver    Specify syntax version. The following are available: 2.4.0, 2.8.4, 2.8.6, 2.9.0\n";
    print "  -w        Enable warnings\n";
    exit 1;
}

my $version = "2.9.0";
# Get the version to know which checks to load
if ($opt{t}) {
    $version = $opt{t};
    print "Version: <$version>\n";
    if( $version !~ /2\.4\.0|2\.4\.5|2\.8\.4|2\.8\.6|2\.9\.0/) {
        print "$version syntax not supported\n";
	    exit 1;
    }
} else {
    print "Version(default): $version\n";
}


my @a_rule_actions = ("alert", "log", "pass", "drop", "reject", "sdrop");
my @a_rule_protos = ("tcp", "udp", "icmp", "ip");
my @a_rule_dirs = ("<>", "->");
my @a_rule_refs = ("bid","bugtraq", "Cve", "cve", "nessus", "arachnids", "mcafee", "url","et","telus","secunia","MCAFEE");
my @a_rule_classtypes = ("attempted-admin", "attempted-user", "shellcode-detect", "successful-admin", 
                         "successful-user", "trojan-activity", "unsuccessful-user", "web-application-attack", 
                         "attempted-dos", "attempted-recon", "bad-unknown", "denial-of-service", "misc-attack",
                         "non-standard-protocol", "rpc-portmap-decode", "successful-dos", 
                         "successful-recon-largescale", "successful-recon-limited", "suspicious-filename-detect", 
                         "suspicious-login", "system-call-detect", "unusual-client-port-connection", 
                         "web-application-activity", "icmp-event", "misc-activity", "network-scan", 
                         "not-suspicious", "protocol-command-decode", "string-detect", "unknown",
                         "tcp-connection", "trojan-activity", "icmp-event", "kickass-porn", 
                         "policy-violation", "default-login-attempt");

my @a_rule_flow_states = ("established", "stateless");
my @a_rule_flow_dirs = ("to_client", "to_server", "from_client", "from_server");
my @a_rule_flow_opts = ("no_stream", "only_stream");

my @a_rule_modifiers = ("depth", "offset", "distance", "within", "nocase", "rawbytes");

if ( $version =~ /(2\.8\.4|2\.8\.6|2\.9\.0)/) {
   push (@a_rule_modifiers, "fast_pattern");
   push (@a_rule_modifiers, "http_client_body");
   push (@a_rule_modifiers, "http_cookie");
   push (@a_rule_modifiers, "http_header");
   push (@a_rule_modifiers, "http_method");
   push (@a_rule_modifiers, "http_uri");
}

if ( $version =~ /(2\.8\.6|2\.9\.0)/) {
   push (@a_rule_modifiers, "replace");
   push (@a_rule_modifiers, "http_raw_cookie");
   push (@a_rule_modifiers, "http_raw_header");
   push (@a_rule_modifiers, "http_raw_uri");
   push (@a_rule_modifiers, "http_stat_msg");
   push (@a_rule_modifiers, "http_stat_code");
   push (@a_rule_modifiers, "http_encode");
   push (@a_rule_modifiers, "file_data");
}
 

my @a_rule_modifiables = ("content", "uricontent", "file_data");

my @a_rule_relativees = ("content", "byte_jump", "pcre");

# Protocols that support flow in all versions
my @a_rule_flow_protos = ("tcp");

# within is very special -.-
my @a_rule_within_pmatch = ("content");
my @a_rule_within_prel = ("byte_jump", "pcre");
my @a_rule_within_nrel = ("uricontent");



# Convert them to hashes for speed optimization
my %rule_actions = map { $_ => 1 } @a_rule_actions;
my %rule_protos = map { $_ => 1 } @a_rule_protos;
my %rule_dirs = map { $_ => 1 } @a_rule_dirs;
my %rule_refs = map { $_ => 1 } @a_rule_refs;
my %rule_classtypes = map { $_ => 1 } @a_rule_classtypes;
my %rule_flow_states = map { $_ => 1 } @a_rule_flow_states;
my %rule_flow_dirs = map { $_ => 1 } @a_rule_flow_dirs;
my %rule_flow_opts = map { $_ => 1 } @a_rule_flow_opts;
my %rule_modifiers = map { $_ => 1 } @a_rule_modifiers;
my %rule_modifiables = map { $_ => 1 } @a_rule_modifiables;
my %rule_relativees = map { $_ => 1 } @a_rule_relativees;
my %rule_within_pmatch = map { $_ => 1 } @a_rule_within_pmatch;
my %rule_within_prel = map { $_ => 1 } @a_rule_within_prel;
my %rule_within_nrel = map { $_ => 1 } @a_rule_within_nrel;
my %rule_flow_protos = map { $_ => 1 } @a_rule_flow_protos;

my %rule_detection_filter_opts = ( "track" => [qr/^(by_src|by_dst)$/,1],
                                   "count" => [qr/^\d+$/,1],
                                   "seconds" => [qr/^\d+$/,1]);

my %rule_threshold_opts = ("type"  => [qr/^(limit|threshold|both)$/,1],
                           "track" => [qr/^(by_src|by_dst)$/,1],
                           "count" => [qr/^\d+$/,1],
                           "seconds" => [qr/^\d+$/,1]);

my %rule_asn1_opts = ("oversize_length"    => [qr/^\d+$/, 0],
                      "absolute_offset"    => [qr/^\d+$/, 0],
                      "relative_offset"    => [qr/^-?\d+$/, 0],
                      "bitstring_overflow" => [1,0],
                      "double_overflow"    => [1,0]);

my %rule_isdataat_opts = ("relative"  => [1,0],
                          "rawbytes" => [1,0]);


my %rule_byte_endian = ( "big" => 1, "little" => 1 );
my %rule_byte_repr = ( "dec" => 1, "oct" => 1, "hex" => 1 );
my %rule_byte_jump_opts = ( "string" => 1, "relative" => 1, "align" => 1, "from_beginning" => 1,
	            		    "multiplier" => qr/^\d+$/);
my %rule_byte_test_opts = ( "string" => 1, "relative" => 1);
my %rule_byte_opts = ( 'byte_jump' => \%rule_byte_jump_opts, 'byte_test' => \%rule_byte_test_opts );
my %rule_fast_pattern_opts = ( "only"	=> [1,0],
                               "offset" => [qr/^\d+$/, 0],
                               "length" => [qr/^\d+$/, 0],
                             );

my %checks = (  "action"    => sub { return $rule_actions{shift @_} },
                "proto"     => sub { return $rule_protos{shift @_} },
                "direction" => sub { return $rule_dirs{shift @_} },
                "src"	    => sub { return validate_host(shift @_) },
                "dst"	    => sub { return validate_host(shift @_) },
                "src_port"  => sub { return validate_port(shift @_) },
                "dst_port"  => sub { return validate_port(shift @_) },
                "opts"      => sub { return validate_opts(@_) }
             );

my %opt_regex = ( "msg"		=> qr/^\".+\"$/,
                  "metadata"	=> qr/^.+$/,
                  "reference" 	=> qr/^\w+\s*,\s*.+$/,
                  "classtype"	=> qr/^.+$/,
                  "sid"		=> qr/^\d+$/,
                  "gid"		=> qr/^\d+$/,
                  "rev"		=> qr/^\d+$/,
                  "priority"	=> qr/^\d+$/,
                  "depth"	=> qr/^\d+$/,
                  "offset"	=> qr/^\d+$/,
                  "distance"	=> qr/^-?\d+$/,
                  "within"	=> qr/^\d+$/,
                  "content"	=> qr/^!?\s*\".+\"$/,
                  "isdataat"	=> qr/^\d+(\s*,.+)?$/,
                  "uricontent"	=> qr/^!?\s*\".+\"$/,
                  "pcre"	=> qr/^!?\s*\"\s*(m(.).+(\2)|\/.+\/)[ismxAEGRUBPHMCOIDKYS]*\s*\"$/,
                  "byte_test"	=> qr/\d+\s*,\s*!?\s*(?:[<>=!&-\^]|<=|>=),.+?,\s*-?\d+\s*(,\s*.+)?/,
                  "byte_jump"	=> qr/\d+\s*,\s*-?\d+\s*(,\s*.+)?/,
                  "fragoffset"  => qr/^(<|>)?\s*\d+$/,
                  "ttl" 	=> qr/^((<|>)?\s*\d+|\d+-\d+)$/,
                  "tos" 	=> qr/^!?\s*\d+$/,
                  "id" 		=> qr/^\d+$/,
                  "ipopts" 	=> qr/^(rr|eol|nop|ts|sec|lsrr|ssrr|satid|any)$/,
                  "fragbits" 	=> qr/^[\+\*!]?[MDR]+[\+\*!]?$/,
                  "dsize" 	=> qr/^[<>]?\s*\d+(\s*<>\s*\d+)?$/,
                  "flags" 	=> qr/^[\+\*!]?[FSRPAU120]+[\+\*!]?(\s*,\s*[FSRPAU120]+)?$/,
                  "flow" 	=> qr/^.+$/,
                  "flowbits"    => qr/^((set|unset|toggle|isset|isnotset)\s*,\s*.+?|(reset|noalert))+$/,
                  "seq" 	=> qr/^\d+$/,
                  "ack" 	=> qr/^\d+$/,
                  "window" 	=> qr/^!?\s*\d+$/,
                  "itype" 	=> qr/^[<>]?\d+(\s*<>\s*\d+)?$/,
                  "icode" 	=> qr/^[<>]?\d+(\s*<>\s*\d+)?$/,
                  "icmp_id" 	=> qr/^\d+$/,
                  "icmp_seq" 	=> qr/^\d+$/,
                  "rpc" 	=> qr/^\d+\s*(,\s*(\d+|\*)){0-2}$/,
                  "ip_proto" 	=> qr/^[!<>]?\w+$/,
                  "logto"	=> qr/^\".+\"$/,
                  "session"	=> qr/^(printable|all)$/,
                  "resp"	=> qr/^(rst_snd|rst_rcv|rst_all|icmp_net|icmp_host|icmp_port|icmp_all)(\s*,\s*(rst_snd|rst_rcv|rst_all|icmp_net|icmp_host|icmp_port|icmp_all))*$/,
                  "react"	=> qr/^(block|warn)(\s*,\s*msg)$/,
                  "tag"		=> qr/^(session|host)(\s*,\s*\d+\s*,\s*(packets|seconds))?(\s*,\s*(src|dst))?$/,
                  "fwsam"	=> qr/^(src|source|dst|dest|destination)(\[(in|out|either)\])?(\s*,\s*(\s*\d+ (seconds|minutes|hours|days|months|years))+|(0|inf|perm))?/,
                  "threshold"	=> qr/^.+$/,
		   );

if ( $version =~ /(2\.8\.4|2\.8\.6|2\.9\.0)/) {
        %opt_regex->{"fast_pattern"}		= qr/^\s*(only|\s*\d+\s*,\s*\d+\s*)?\s*$/;
        %opt_regex->{"stream_size"}		= qr/^\s*(server|client|both|either)\s*,\s*(<|>|=|!=|<=|>=)\s*,\s*\d+\s*$/;
        %opt_regex->{"urilen"}			= qr/^([<>]?\s*\d+|(\d+\s*<>\s*\d+)?)$/;
        %opt_regex->{"asn1"}			= qr/^.+$/;
        %opt_regex->{"cvs"}			= qr/^invalid-entry$/;
        %opt_regex->{"activates"}		= qr/^\d+$/;
        %opt_regex->{"activated_by"}		= qr/^\d+$/;
        %opt_regex->{"count"}			= qr/^\d+$/;
}

if ( $version =~ /(2\.8\.6|2\.9\.0)/) {
        %opt_regex->{"replace"}			= qr/^\".+\"$/;
        %opt_regex->{"detection_filter"} 	= qr/^\s*track\s+(by_src|by_dst)\s*,\s*count\s+\d+\s*,\s*seconds\s+\d+\s*$/;
}

if ( $version =~ /(2\.9\.0)/) {
        %opt_regex->{"stream_reassemble"}	= qr/^\s*(enable|disable)\s*,\s*(server|client|both)\s*(,\s*noalert\s*(,\s*fastpath)?)?\s*$/;
        %opt_regex->{"ssl_version"}		= qr/^\s*!?\s*(sslv2\s*|\s*sslv3\s*|\s*tls1\.0\s*|\s*tls1\.1\s*|\s*tls1\.2)\s*(,\s*!?\s*(sslv2\s*|\s*sslv3\s*|\s*tls1\.0\s*|\s*tls1\.1\s*|\s*tls1\.2))*\s*$/;
        %opt_regex->{"ssl_state"}		= qr/^\s*!?\s*(\s*client_hello\s*|\s*server_hello\s*|\s*client_keyx\s*|\s*server_keyx\s*|\s*unknown\s*)\s*(,\s*!?\s*(\s*client_hello\s*|\s*server_hello\s*|\s*client_keyx\s*|\s*server_keyx\s*|\s*unknown\s*))*\s*$/;
        %opt_regex->{"base64_decode"}		= qr/^\s*(\s*offset\s+\d+\s*,?|\s*bytes\s+\d+\s*,?|\s*relative\s*,?){0,3}\s*$/;
        %opt_regex->{"byte_extract"}		= qr/^\s*\d+\s*,\s*[^,]+\s*,\s*[^,]+\s*(\s*,\s*multiplier\s+\d+|\s*,\s*align\s+\d+|\s*,\s*(relative|big|little|dce|hex|dec|oct|string))*\s*$/;

	# Byte_extract extracted values can be used in the following modifiers (it's usually a name, not digits, so overwritting the regexs)
        %opt_regex->{"depth"}			= qr/^.*$/;
        %opt_regex->{"offset"}			= qr/^.*$/;
        %opt_regex->{"distance"}		= qr/^-?.*$/;
        %opt_regex->{"within"}			= qr/^.*$/;
        %opt_regex->{"byte_test"}		= qr/\d+\s*,\s*!?\s*(?:[<>=!&-\^]|<=|>=),[^,]+?,\s*-?[^,]+\s*(,\s*.+)?/;
        %opt_regex->{"byte_jump"}		= qr/\d+\s*,\s*-?[^,]+\s*(,\s*.+)?/;
        %opt_regex->{"isdataat"}		= qr/^[^,]+(\s*,.+)?$/;
}

my %opt_checks = (  "reference"    	=> sub { my $t = validate_reference(@_); return $t; },
                    "sid"   	        => sub { my $t = validate_sid(@_); return $t; },
                    "classtype"    	=> sub { my $t = validate_classtype(@_); return $t; },
                    "nocase"	   	=> sub { my $t = validate_modcount(@_,1); return $t; },
                    "rawbytes" 	   	=> sub { my $t = validate_modcount(@_,1); return $t; },
                    "depth" 	   	=> sub { my $t = validate_modcount(@_,1);  return $t; },
                    "offset" 	   	=> sub { my $t = validate_modcount(@_,1);  return $t; },
                    "distance" 	   	=> sub { my $t = validate_modcount(@_,1);  return $t; },
                    "within" 	   	=> sub { my $t = validate_within(@_); return $t; },
                    "isdataat"	   	=> sub { my $t = validate_isdataat(@_); return $t; },
                    "byte_test"	   	=> sub { my $t = validate_bytefunc(@_); return $t; },
                    "byte_jump"	   	=> sub { my $t = validate_bytefunc(@_); return $t; },
                    "regex" 	   	=> sub { my $t = warn_deprecated(@_); return $t; },
                    "content-list" 	=> sub { my $t = warn_deprecated(@_); return $t; },
                    "flow"	    	=> sub { my $t = validate_flow(@_); return $t; },
                    "pcre"	    	=> sub { my $t = validate_pcre(@_); return $t; },
                    "sameip"       	=> sub { return 1; },
                    "ftpbounce"    	=> sub { return 1; },
		# Deprecated:
                    "regex"	    	=> sub { return 1; },
                    "content_list"    	=> sub { return 1; },
                    "threshold"    	=> sub { my $t = validate_byhash(@_,\%rule_threshold_opts); return $t; }
                 );

if ( $version =~ /(2\.8\.4|2\.8\.6|2\.9\.0)/) {
        %opt_checks->{"fast_pattern"}		= sub { my $t = validate_fastpattern(@_); return $t; };
	%opt_checks->{"http_header"}		= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_client_body"}	= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_cookie"}		= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_method"}		= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_uri"}		= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"asn1"}		    	= sub { my $t = validate_byhash(@_,\%rule_asn1_opts); return $t; };
        %opt_checks->{"dce_stub_data"}		= sub { return 1; };
        %opt_checks->{"dce_iface"}		= sub { return 1; };
        %opt_checks->{"dce_opnum"}		= sub { return 1; };
}

if ( $version =~ /(2\.8\.6|2\.9\.0)/) {
        %opt_checks->{"replace"} 	   	= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"detection_filter"}	= sub { my $t = validate_byhash(@_,\%rule_detection_filter_opts); return $t; };
        %opt_checks->{"http_raw_uri"}		= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_raw_cookie"}	= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_raw_header"}	= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_stat_code"}    	= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_stat_msg"}     	= sub { my $t = validate_modcount(@_,1);  return $t; };
        %opt_checks->{"http_encode"} 	   	= sub { return 1; };
        %opt_checks->{"file_data"}          = sub { return 1; };
}

if ( $version =~ /2\.9\.0/) {
        %opt_checks->{"base64_data"}  	        = sub { return 1; };
}

my @files;
my $rule_count = 0;
my $errors = 0;
my $warnings = 0;
my @errors;
my @warnings;
my %sids;

foreach (@ARGV) {
    if ((-r $_) and not (-d $_)) {
        push(@files, $_);
    } elsif ($opt{w}) {
        print STDERR "Warning: Can't read \"$_\", either does not exist or no file. Ignoring...\n";
    }
}

unless (@files) {
	print STDERR "Error: No files to process, exiting...\n";
	exit 1;
}


pinfo("Starting validation process...");


foreach my $file (@files) {
    open(INFILE, $file) or die "Fatal: Can't read \"$file\" (file vanished?), aborting...\n";
    pinfo("Processing $file...");

    my $rule_string = "";
    my $lineno = 0;
    my $multiline = 0;

    while (<INFILE>) {
        chomp;
        
        # Ignore comments and empty lines
        if ($_ =~ /^\s*\#.*/ or $_ =~ /^\s*$/) {
            next;
        } else {
            unless ($rule_string) {
                $lineno = $.;
            }
            $rule_string .= trim($_);
        }

        # Check if the line ends here or is continued (multi line rule)
        if ($rule_string =~ /(.*)\\\s*$/) {
            # Remove trailing backslash and whitespace
            $rule_string = "$1 ";
            $multiline = 1;
            next;
        }

        if ($multiline) {
            $lineno .= "-" . $.;
        }
        my $rule = Parse::Snort->new();
        $rule->parse($rule_string);

        if (validate_rule($rule)) {
            $rule_count++;
        } else {
            my $err;
            if ($opt{s}) {
                my $sid = get_sid($rule_string);
                $err = "Error ($file:$lineno SID $sid):";
            } else {
                $err = "Error ($file:$lineno):";
            }

            foreach (reverse @errors) {
                $err .= " $_";
            }

            print STDERR "$err\n";

            if ($opt{a}) {
                exit 1;
            } else {
                $errors++;
            }
        }

        if (@warnings and $opt{w}) {
            my $warn;
            if ($opt{s}) {
                my $sid = get_sid($rule_string);
                $warn = "Warning ($file:$lineno SID $sid):";
            } else {
                $warn = "Warning ($file:$lineno):";
            }
            foreach (reverse @warnings) {
                $warn .= " $_";
            }
            print STDERR "$warn\n";
            $warnings++;
        }
        
        # Reset rule string
        $rule_string = "";
        $multiline = 0;
        @errors = ();
        @warnings = ();
    }
    close INFILE;
}

pout("Done! Validated $rule_count rules ($errors errors, $warnings warnings). Syntax used: $version.");

if ($errors or $warnings) { exit 1; }


sub validate_rule {
    my ($rule) = @_;

    my %rulehash = %$rule;
    my @history = ();

    if ($opt{d}) {
        print_rule($rule);
    }


    my $hasopts = 0;

    foreach my $key (keys %rulehash) {
        my $sub = $checks{$key};

        my $arg = $rulehash{$key};
        my $err;

        if ($key eq 'opts') {
            $hasopts = 1;
        }

        if (ref($arg)) {
            $err = "Error in $key field:";
        } else {
            $arg = $opt{i} ? lc $arg : $arg;
            $err = "Error in $key field: \"$arg\" not accepted here.";
        }

        push(@history, $arg);

        unless (&$sub($arg, \@history)) {
            perr($err);
            return 0;
        }
    }

    unless ($hasopts) {
        perr("Rule has no options.");
        return 0;
    }

    return 1;
}

sub validate_host {
    my ($hoststring) = @_;
    
    my @hosts;

    if ($hoststring =~ /^!?\s*\[([\.,\/\$\w]+)\]$/) {
        push(@hosts, split(',', $1));
    } else {
        push(@hosts, $hoststring);
    }

    foreach my $host (@hosts) {
        my $orighost = $host;

        $host =~ s/^!\s*//;

        # Host variable
        if ($host =~ /^\$\w+$/) { next; }
        if ($host =~ /^any$/) { next; }

        # This is an ugly hack, Net::IP does not support unnormalized CIDR masks
        my $ip;
        eval {
            ($ip) = Net::CIDR::cidr2range("$host");
        };

        if ($?) {
            perr("Invalid IP specification \"$host\"");
            return 0;
        }

        my $ipobj = new Net::IP($ip);

        unless ($ipobj) {
            perr("Invalid IP specification \"$host\" (" . Net::IP::Error() . ")");
            return 0;
        }
    }

    return 1;
}

sub validate_port {
    my ($portstring) = @_;
    my $origport = $portstring;

    $portstring =~ s/^!\s*//;

    my @portranges = ($portstring);
    my @ports;

    if ($portstring =~ /^\[([\:,\$\w]+)\]$/) {
        @portranges = split(',', $1);
    }

    foreach my $portrange (@portranges) { 
        if ($portrange =~ /^(\$\w+|any|\d*):(\$\w+|any|\d*)$/) {
            my @cports = ($1,$2);

            unless (length($cports[0]) or length($cports[1])) {
                perr("Port specification incomplete.");
                return 0;
            }

            if (int($cports[0]) and int($cports[1]) and ($cports[0] > $cports[1])) {
                perr("Invalid port range specification \"$origport\".");
                return 0;
            }

            push(@ports, @cports);
        } elsif ($portrange =~ /^(\$\w+|any|\d*)$/) {
            push(@ports,$1);
        } else {
            perr("Invalid port specification \"$origport\".");
            return 0;
        }
    }

    foreach my $port (@ports) {
        if ($port =~ /^\$\w+$/ or $port =~ /^(any)?$/) { next; }
        unless ($port =~ /^\d+$/) {
            perr("Invalid port specification \"$port\"");
            return 0;
        }
        unless ($port >= 0 and $port <= 65535) {
            perr("Port \"$port\" is out of range.");
            return 0;
        }
    }

    return 1;
}

sub validate_opts {
    my ($optref, $histr) = @_;

    my @opts = @$optref;
    my @hist = (['main', $histr]);

    foreach my $optref (@opts) {
        unless (ref $optref) {
            perr("Failed to obtain option.");
            return 0;
        }
        my @opt = @$optref;
        my $arg = $opt{i} ? trim(lc shift @opt) : trim(shift @opt);
        my $sub = $opt_checks{$arg};
        my $regex = $opt_regex{$arg};

        unless ($regex or $sub) {
            perr("Unknown option \"$arg\" used.");
            return 0;
        }

        if (not $regex and scalar(@opt)) {
            perr("Non-parameter option \"$arg\" used with parameter(s).");
            return 0;
        }

        if ($regex) {
            my $topt = trim($opt[0]);
            unless ($topt =~ $regex) {
                perr("Ill-formatted parameter(s) to option \"$arg\".");
                return 0;
            }
        }

        if ($sub) {
            unless (&$sub($arg, \@opt, \@hist)) {
                perr("Option \"$arg\":");
                return 0;
            }
        }

        push(@hist, [$arg, \@opt]);
    }

    return 1;
}

sub validate_reference {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;

    my ($refp,$ref) = split(',', $opt[0]);
    $refp = trim($refp);

    unless ($rule_refs{$refp}) {
        perr("Unknown reference provider \"$refp\"");
        return 0;
    }

    return 1;
}

sub validate_sid {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;

    my $sid = trim($opt[0]);
    
    if ($opt{l} and $sid >= 2020000) {
        perr("SID value too high (must be less than 3000000 for et rule)");
        return 0;
    }

    if ($opt{l} and $sid <= 1000000) {
        perr("SID value too low (must be greater than 1000000 for local rule)");
        return 0;
    }

    if ($sids{$sid}) {
        pwarn("Duplicate sid detected.");
    }

    $sids{$sid} = 1;

    return 1;
}

sub validate_classtype {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;

    my $classtype = $opt{i} ? lc trim($opt[0]) : trim($opt[0]);

    unless ($rule_classtypes{$classtype}) {
        pwarn("Non-standard classtype \"$classtype\" used");
    }

    return 1;
}

sub validate_modcount {
    my ($arg, $optref, $histref, $modcount) = @_;
    my @opt = @$optref;
    my @history = @$histref;

    my $mcnt = 0;

    foreach my $t (reverse @history) {
        my ($harg, $paramsref) = @$t;
        if ($rule_modifiables{$harg}) { $mcnt++; }
    }

    if ($mcnt < $modcount) {
        if ($rule_modifiers{$arg}) {
            perr("Misplaced modifier, not enough modifiable statements here.");
        } else {
            perr("Option does not have enough modifiable statements here.");
        }
        return 0;
    }

    return 1;
}

sub validate_relative {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;
    
    my $opt = strip($opt[0]);

    if ($opt =~ /relative/i) {
	    my @history = @$histref;

	    foreach my $t (reverse @history) {
            my ($harg, $paramsref) = @$t;
            if ($rule_relativees{$harg}) { return 1; }
	    }

	    perr("Option with \"relative\" keyword where nothing to be relative to.");
	    return 0;
    }

    return 1;
}

sub validate_isdataat {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;
    my $optstring;

    if (trim($opt[0]) =~ $opt_regex{$arg}) {
        $optstring = $1;
        $optstring =~ s/^,//;
    }

    unless(validate_relative($arg, $optref, $histref)) {
        return 0;
    }

    unless(validate_byhash($arg, [$optstring], $histref, \%rule_isdataat_opts)) {
        return 0;
    }

    # This is an undocumented feature, seems to be used in one VRT snort rule
    if ($optstring =~ /rawbytes/) {
        pwarn("Undocumented use of \"rawbytes\" modifier to \"$arg\" option");
    }

    return 1;
}
sub validate_within {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;
    my @history = @$histref;

    my ($pmatch,$prel,$nwarn) = (0,0,0);

    foreach my $t (reverse @history) {
        my ($harg, $paramsref) = @$t;
        if ($rule_within_pmatch{$harg}) { $pmatch++; }
        elsif ($rule_within_prel{$harg}) { $prel++; }
        elsif ($rule_within_nrel{$harg}) {
            if ($pmatch <= 1 and not $prel and not $nwarn) {
                pwarn("Option \"$arg\" possibly used with uricontent as intended reference.");
                $nwarn = 1;
            }
        }
    }

    unless ($pmatch > 1 or ($pmatch and $prel)) {
        if ($pmatch) {
            unless ($nwarn) {
            pwarn("Option \"$arg\" with limited effect (use depth instead).");
            }
        } else {
            perr("Error: Option requires a preceeding pattern match.");
            return 0;
        }
    }

    return 1;
}

sub validate_bytefunc {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;

    unless (validate_relative($arg, $optref, $histref)) {
        return 0;
    }

    my $optstring = normalize($opt[0]);
    my %have;
    my %my_rule_byte_opts = %{$rule_byte_opts{$arg}};

    if ($optstring =~ $opt_regex{$arg}) {
        my $options = $1;
        my @opts = split(',', $options);
        foreach my $opt (@opts) {
            $opt = trim($opt);
            unless ($opt) { next; }
            my ($param, $larg) = split(' ', $opt);
            $param = trim($param);
            $larg = trim($larg);
            if ($rule_byte_repr{$param}) {
                if ($have{'rule_byte_repr'}) {
                    perr("Duplicate or exclusive encoding parameters mixed in statement");
                    return 0;
                } else {
                    $have{'rule_byte_repr'} = 1;
                }
            } elsif ($rule_byte_endian{$param}) {
                if ($have{'rule_byte_endian'}) {
                    perr("Duplicate or exclusive endian parameters mixed in statement");
                    return 0;
                } else {
                    $have{'rule_byte_endian'} = 1;
                }
            } elsif ($my_rule_byte_opts{$param}) {
                if ($have{$param}) {
                    perr("Duplicate parameter \"$param\" in statement");
                    return 0;
                } else {
                    unless (not ref($my_rule_byte_opts{$param}) or $larg =~ $my_rule_byte_opts{$param}) {
                        perr("Argument to parameter \"$param\" ill-formatted in statement");
                        return 0;
                    }
                    $have{$param} = 1;
                }
            } else {
                perr("Unknown parameter \"$param\" in statement");
                return 0;
            }
        }

        if ($have{'rule_byte_repr'} and not $have{'string'}) {
            perr("Endian parameters without \"string\" option in statement");
            return 0;
        }
    }

    return 1;
}

sub validate_fastpattern {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;

    foreach my $t (@$histref) {
	my ($harg, $paramsref) = @$t;
	if ($harg =~ /^http_cookie$/i) {
	    perr("Option can't be used with \"http_cookie\" modifier");
	    return 0;
	} elsif ($harg =~ /^(uri)?content$/i) {
	    my @params = @$paramsref;
            #print @params;
            #print "\nparams[0]:" + $params[0] +"\n";
            #exit;
	    #my $param = trim $params[0];
	    #if ($param =~ /^!/) {
            #perr("Option can't be used with negated modifiables");
            return 1;
	    #}
	}
    }

    return validate_modcount(@_,2);
}

sub validate_flow {
    my ($arg, $optref, $histref) = @_;
    my @opt = @$optref;

    my $flow = strip($opt[0]);

    my @flows = split(',', $flow);

    my ($have_state, $have_dir, $have_opt) = (0,0,0);

    my @history = @$histref;

    foreach my $t (@history) {
        my ($harg, $paramsref) = @$t;
        if ($harg eq 'main') {
            my $proto = $$paramsref[1];
            unless ($rule_flow_protos{$proto}) {
                pwarn("Protocol \"$proto\" possibly not supported with \"flow\" keyword.");
            }
        }
    }

    foreach my $flowopt (@flows) {
        if ($rule_flow_states{$flowopt}) {
            if ($have_state) {
                perr("Multiple state options in flow arguments.");
                return 0;
            }
            $have_state = 1;
        } elsif ($rule_flow_opts{$flowopt}) {
            if ($have_opt) {
                perr("Multiple stream options in flow arguments.");
                return 0;
            }
            $have_opt = 1;
        } elsif ($rule_flow_dirs{$flowopt}) {
            if ($have_dir) {
                perr("Multiple direction options in flow arguments.");
                return 0;
            }
            $have_dir = 1;
        } else {
            perr("Unknown option \"$flowopt\" in flow arguments.");
            return 0;
        }
    }

    return 1;
}

sub validate_pcre {
    my ($arg, $optref, $histref) = @_;
    my @opts = @$optref;

    foreach my $opt (@opts) {
        my $regex = trim($opt);
        eval { '' =~ /$regex/ };
        if ($@) {
            my $err = $@;
            $err =~ s/at .+? line \d+.+$//;
            chomp($err);
            perr("Invalid PCRE expression: \"$regex\" ($err).");
            return 0;
        }

    }

    return 1;
}

sub validate_byhash {
    my ($arg, $optref, $histref, $vref) = @_;
    my @opt = @$optref;

    my %vhash = %$vref;

    my $optstring = normalize($opt[0]);

    my @opts = split(',', $optstring);

    my %have;

    foreach my $opt (@opts) {
        my ($param, $larg) = split(' ', $opt);
        $param = trim($param);
        $larg = trim($larg);
        if ($vhash{$param}) {
            if ($have{$param}) {
                perr("Duplicate parameter \"$param\" in statement");
                return 0;
            } else {
                my ($regex, $mand) = @{$vhash{$param}};
                unless (not ref($regex) or $larg =~ $regex) {
                    perr("Argument to parameter \"$param\" ill-formatted in statement");
                    return 0;
                }
                $have{$param} = 1;
            }
        } else {
            perr("Unknown parameter \"$param\" in statement");
            return 0;
        }
    }

    foreach my $param (keys %vhash) {
        my ($regex, $mand) = @{$vhash{$param}};
        unless ($have{$param} or not $mand) {
            perr("Missing parameter \"$param\" in statement");
            return 0;
        }
    }

    return 1;
}

sub warn_deprecated {
    my ($arg, $optref, $histref) = @_;
    pwarn("Deprecated option $arg in use.");
    return 1;
}

sub trim {
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}

sub strip {
    my $string = shift;
    $string =~ s/\s+//g;
    return $string;
}

sub normalize {
    my $string = shift;
    $string =~ s/\s+/ /g;
    return $string;
}

sub print_rule {
    my ($rule) = @_;
    
    print Dumper $rule;
    print "\n";
}

sub get_sid {
    my ($rule_string) = @_;

    if ($rule_string =~ /sid:\s*(\d+)/i) {
        return $1;
    } else {
        return "N/A";
    }
}

sub perr {
    my ($string) = @_;
    push(@errors, $string);
}

sub pwarn {
    my ($string) = @_;
    push(@warnings, $string);
}

sub pout {
    my ($string) = @_;
    unless ($opt{q}) {
        print "$string\n";
    }
}

sub pinfo {
    my ($string) = @_;
    if ($opt{v}) {
        print "$string\n";
    }
}
