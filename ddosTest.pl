#!/usr/bin/env perl

use strict;
use warnings;

# Versioning info for looking all official
our $VERSION = 0.1;

# Number to watch out for
my $THRESHOLD = 5;

# Load the exclusions list
my $EXCLUSIONS = "exclusions.txt";
my @exclusions;
if (-e $EXCLUSIONS) {
    open my $fh1, '<', $EXCLUSIONS;
    @exclusions = <$fh1>;
    close $fh1;
}
else { };

# Read the log file or die trying
my $file = shift or die "Usage: $0 <log file>\n";
open my $fh2, '<', $file or die "Could not open '$file' $!";
my @logs = <$fh2>;
close $fh2;

# Time and space adventures; first key is firewall, second is attacker
my $hits = {};
foreach my $log (@logs) {

    if (
        $log =~ m{
            (\d+[.][\d.]+)  # Firewall IP, since it's the first on the line
            .*              # Other crap
            src=([\d.]+)    # Attacker IP, neatly packaged
        }msx
    )
    {

        # First subexpression from regex is firewall, second attacker
        my ( $firewall, $attacker ) = ( $1, $2 );

        # Create a new hash for the firewall if needed
        if ( !exists $hits->{$firewall} ) {
            $hits->{$firewall} = {};
        }

        # Start a new count for this attacker if needed
        if ( !exists $hits->{$firewall}->{$attacker} ) {
            $hits->{$firewall}->{$attacker} = 0;
        }

        # Increment the count for this firewall and attacker
        $hits->{$firewall}->{$attacker}++;
    }
}

# See if any IPs match or exceed the acceptable limit
foreach my $firewall ( keys %{$hits} ) {
    foreach my $attacker ( keys %{ $hits->{$firewall} } ) {
        if ( /^$attacker/i ~~ @exclusions ) { }
        else {
            if ( $hits->{$firewall}->{$attacker} >= $THRESHOLD ) {
                my $message =
                "The firewall at $firewall says $attacker showed up $hits->{$firewall}->{$attacker} times; this may be an attack\n";
                print $message;

                # If so, throw them into syslog(3) with a custom tag
                exec "logger -p auth.alert -t HACKS '$message'";
            }
        }
    }
}

# (c) 2015 SmartSystems, Inc.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
