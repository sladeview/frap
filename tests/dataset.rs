use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::{BufRead, BufReader},
    panic,
    path::PathBuf,
};

#[test]
#[ignore = "requires the local real-world dataset; see test-data/README.md"]
fn audits_real_world_dataset_without_panicking() {
    let path = env::var_os("FRAP_DATASET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("test-data/real-world-1m.tnc2"));
    let file = File::open(&path)
        .unwrap_or_else(|error| panic!("failed to open dataset {}: {error}", path.display()));
    let mut reader = BufReader::new(file);
    let mut raw = Vec::new();
    let mut total = 0_u64;
    let mut parsed = 0_u64;
    let mut parse_errors = BTreeMap::<String, u64>::new();
    let mut panics = 0_u64;

    while reader.read_until(b'\n', &mut raw).expect("read dataset") != 0 {
        if raw.last() == Some(&b'\n') {
            raw.pop();
        }
        total += 1;

        match panic::catch_unwind(|| frap::parse(&raw)) {
            Ok(Ok(_)) => parsed += 1,
            Ok(Err(error)) => {
                *parse_errors
                    .entry(error.code.as_str().to_string())
                    .or_default() += 1;
            }
            Err(_) => panics += 1,
        }
        raw.clear();
    }

    eprintln!("dataset: {}", path.display());
    eprintln!("packets: {total}");
    eprintln!("parsed: {parsed}");
    eprintln!("parse errors: {}", total - parsed - panics);
    eprintln!("panics: {panics}");
    for (code, count) in parse_errors {
        eprintln!("  {code}: {count}");
    }

    assert!(total > 0, "dataset is empty");
    assert_eq!(panics, 0, "parser panicked on {panics} dataset packets");
}
