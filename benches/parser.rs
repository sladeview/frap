use std::hint::black_box;
use std::time::{Duration, Instant};

const PACKETS: &[&[u8]] = &[
    b"2W0FWJ-2>APRS,WIDE1-1,WIDE2-1:!6128.23N/02353.52E-PHG2360/Testing",
    b"2W0FWJ-2>TQ4W2V,WIDE2-1,qAo,2W0FWJ:`c51!f?>/]\"3x}=",
    b"2W0FWJ>APRS:T#176,250,053,000,048,,1111,station",
    b"2W0FWJ>APRS:!5120.00N/00300.00W_206/001g003t085r000p000P000h73b10117",
];

fn measure(mut operation: impl FnMut(&[u8]), iterations: u64) -> Duration {
    let started = Instant::now();
    for index in 0..iterations {
        operation(black_box(PACKETS[index as usize % PACKETS.len()]));
    }
    started.elapsed()
}

fn report(name: &str, elapsed: Duration, iterations: u64) {
    let rate = iterations as f64 / elapsed.as_secs_f64();
    let nanoseconds = elapsed.as_nanos() as f64 / iterations as f64;
    println!("{name:>10}: {rate:>12.0} packets/s, {nanoseconds:>8.0} ns/packet");
}

fn main() {
    let iterations = std::env::var("FRAP_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(500_000);

    let borrowed = measure(
        |packet| {
            black_box(frap::parse_ref(packet).unwrap());
        },
        iterations,
    );
    let owned = measure(
        |packet| {
            black_box(frap::parse(packet).unwrap());
        },
        iterations,
    );

    println!("mixed APRS packet benchmark ({iterations} iterations)");
    report("borrowed", borrowed, iterations);
    report("owned", owned, iterations);
}
