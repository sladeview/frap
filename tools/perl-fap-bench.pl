#!/usr/bin/env perl

use strict;
use warnings;
use bytes;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);
use Ham::APRS::FAP qw(parseaprs);

my $path = shift @ARGV or die "usage: perl-fap-bench.pl DATASET [REPEATS]\n";
my $repeats = shift(@ARGV) // 3;
die "REPEATS must be greater than zero\n" unless $repeats =~ /^\d+$/ && $repeats > 0;

open my $dataset, '<:raw', $path or die "open $path: $!\n";
my @packets;
while (defined(my $packet = <$dataset>)) {
    $packet =~ s/\n\z//;
    push @packets, $packet;
}
close $dataset or die "close $path: $!\n";
die "dataset is empty\n" unless @packets;

for my $index (0 .. ($#packets < 9_999 ? $#packets : 9_999)) {
    my %parsed;
    parseaprs($packets[$index], \%parsed, isax25 => 0, accept_broken_mice => 0, raw_timestamp => 1);
}

my @rates;
my $successes = 0;
for my $run (1 .. $repeats) {
    my $started = clock_gettime(CLOCK_MONOTONIC);
    $successes = 0;
    for my $packet (@packets) {
        my %parsed;
        $successes++ if parseaprs(
            $packet,
            \%parsed,
            isax25 => 0,
            accept_broken_mice => 0,
            raw_timestamp => 1,
        ) == 1;
    }
    my $elapsed = clock_gettime(CLOCK_MONOTONIC) - $started;
    my $rate = scalar(@packets) / $elapsed;
    push @rates, $rate;
    printf "run=%d\tseconds=%.6f\tpackets_per_second=%.0f\n", $run, $elapsed, $rate;
}
@rates = sort { $a <=> $b } @rates;
printf "parser=perl-fap\tpackets=%d\tsuccesses=%d\trepeats=%d\tmedian_packets_per_second=%.0f\n",
    scalar(@packets), $successes, $repeats, $rates[int(@rates / 2)];
