use std::{
    env,
    fs::File,
    hint::black_box,
    io::{BufRead, BufReader},
    path::PathBuf,
    time::Instant,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or("usage: corpus-bench CORPUS [REPEATS]")?);
    let repeats = args
        .next()
        .map(|value| value.to_string_lossy().parse::<usize>())
        .transpose()?
        .unwrap_or(3);
    if repeats == 0 {
        return Err("REPEATS must be greater than zero".into());
    }

    let mut packets = Vec::new();
    let mut reader = BufReader::new(File::open(&path)?);
    let mut line = Vec::new();
    while reader.read_until(b'\n', &mut line)? != 0 {
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        packets.push(std::mem::take(&mut line));
    }
    if packets.is_empty() {
        return Err("corpus is empty".into());
    }

    benchmark("frap-borrowed", &packets, repeats, |packet| {
        black_box(frap::parse_ref(black_box(packet))).is_ok()
    });
    benchmark("frap-owned", &packets, repeats, |packet| {
        black_box(frap::parse(black_box(packet))).is_ok()
    });
    Ok(())
}

fn benchmark(parser: &str, packets: &[Vec<u8>], repeats: usize, parse: impl Fn(&[u8]) -> bool) {
    for packet in packets.iter().take(10_000) {
        black_box(parse(black_box(packet)));
    }

    let mut rates = Vec::with_capacity(repeats);
    let mut successes = 0;
    for run in 1..=repeats {
        let started = Instant::now();
        successes = 0;
        for packet in packets {
            if black_box(parse(black_box(packet))) {
                successes += 1;
            }
        }
        let elapsed = started.elapsed();
        let rate = packets.len() as f64 / elapsed.as_secs_f64();
        rates.push(rate);
        println!(
            "parser={parser}\trun={run}\tseconds={:.6}\tpackets_per_second={rate:.0}",
            elapsed.as_secs_f64()
        );
    }
    rates.sort_by(f64::total_cmp);
    println!(
        "parser={parser}\tpackets={}\tsuccesses={successes}\trepeats={repeats}\tmedian_packets_per_second={:.0}",
        packets.len(),
        rates[rates.len() / 2]
    );
}
