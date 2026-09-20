#!/usr/bin/env perl

use strict;
use warnings;
use bytes;
use Ham::APRS::FAP qw(parseaprs);

sub hex_value {
    return '' unless defined $_[0];
    return unpack('H*', $_[0]);
}

my $path = shift @ARGV or die "usage: perl-fap-outcomes.pl DATASET\n";
open my $dataset, '<:raw', $path or die "open $path: $!\n";
binmode STDOUT, ':raw';

while (defined(my $packet = <$dataset>)) {
    $packet =~ s/\n\z//;
    my %parsed;
    my $ok = parseaprs(
        $packet,
        \%parsed,
        isax25 => 0,
        accept_broken_mice => 0,
        raw_timestamp => 1,
    );

    print join(
        "\t",
        $ok == 1 ? 1 : 0,
        defined $parsed{resultcode} ? $parsed{resultcode} : '',
        defined $parsed{type} ? $parsed{type} : '',
        defined $parsed{latitude} ? $parsed{latitude} : '',
        defined $parsed{longitude} ? $parsed{longitude} : '',
        defined $parsed{symboltable} ? ord($parsed{symboltable}) : '',
        defined $parsed{symbolcode} ? ord($parsed{symbolcode}) : '',
        defined $parsed{course} ? $parsed{course} : '',
        defined $parsed{speed} ? $parsed{speed} : '',
        defined $parsed{altitude} ? $parsed{altitude} : '',
        defined $parsed{posambiguity} ? $parsed{posambiguity} : '',
        defined $parsed{messaging} ? $parsed{messaging} : '',
        hex_value($parsed{destination}),
        hex_value($parsed{message}),
        hex_value($parsed{messageid}),
        hex_value($parsed{messageack}),
        hex_value($parsed{messagerej}),
        defined $parsed{telemetry}{seq} ? $parsed{telemetry}{seq} : '',
        map(
            defined $parsed{telemetry}{vals}[$_] ? $parsed{telemetry}{vals}[$_] : '',
            0 .. 4
        ),
        hex_value($parsed{telemetry}{bits}),
        map(
            defined $parsed{wx}{$_} ? $parsed{wx}{$_} : '',
            qw(wind_direction wind_speed wind_gust temp temp_in humidity humidity_in pressure rain_1h rain_24h rain_midnight snow_24h luminosity)
        ),
        hex_value($parsed{wx}{soft}),
        hex_value($parsed{comment}),
        defined $parsed{wx} ? 1 : 0,
    ), "\n";
}

close $dataset or die "close $path: $!\n";
