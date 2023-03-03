use clap::Parser;
use iso8601_timestamp::Timestamp;
use oberon::*;
use rand_core::{OsRng, RngCore};
use std::io::{stdout, Write};
use uuid::Uuid;

#[derive(Parser, Clone, Debug)]
struct Arguments {
    #[clap(
        short,
        long,
        value_name = "COUNT",
        default_value_t = 10000,
        value_parser = clap::value_parser!(u64).range(1..u64::MAX))
    ]
    count: u64,
    #[clap(
        short,
        long,
        value_name = "BLINDING_FACTOR",
        default_value_t = String::from("1234"),
        default_missing_value = "1234"
    )]
    blinding_factor: String,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Sample {
    pub creation_time: i128,
    pub verification_time: i128,
    pub proving_time: i128,
    pub open_time: i128,
    pub blinding: i128,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SampleStatistics {
    pub creation_time: f64,
    pub verification_time: f64,
    pub proving_time: f64,
    pub open_time: f64,
    pub blinding: f64,
}

fn main() {
    let args = Arguments::parse();
    let sk = SecretKey::new(OsRng);
    let pk = PublicKey::from(&sk);

    let mut samples = Vec::with_capacity(args.count as usize);

    let mut last_i_length = Vec::with_capacity(args.count.to_string().len());
    println!("Generating {} samples", args.count);
    print!("Sample ");
    stdout().flush().unwrap();

    for i in 1..=args.count {
        for b in &last_i_length {
            print!("{}", b);
        }
        stdout().flush().unwrap();
        print!("{}", i);
        let i_str = i.to_string();
        while last_i_length.len() < i_str.len() {
            last_i_length.push('\u{8}');
        }

        let id = Uuid::new_v4();
        let id_bytes = id.as_bytes();
        let nonce_time = Timestamp::now_utc();

        let before_create = Timestamp::now_utc();
        let token = Token::new(&sk, id_bytes);
        let after_create = Timestamp::now_utc();
        let token = token.unwrap();

        let before_verify = Timestamp::now_utc();
        let verify_choice = token.verify(pk, id_bytes);
        let after_verify = Timestamp::now_utc();
        assert_eq!(verify_choice.unwrap_u8(), 1u8);

        let nonce_t = Timestamp::now_utc()
            .duration_since(nonce_time)
            .whole_nanoseconds();
        let nonce = nonce_t.to_be_bytes();
        let before_prove = Timestamp::now_utc();
        let proof = Proof::new(&token, &[], id_bytes, &nonce, OsRng);
        let after_prove = Timestamp::now_utc();
        let proof = proof.unwrap();

        let before_open = Timestamp::now_utc();
        let open_choice = proof.open(pk, id_bytes, nonce);
        let after_open = Timestamp::now_utc();
        assert_eq!(open_choice.unwrap_u8(), 1u8);

        let before_blind = Timestamp::now_utc();
        let blinding = Blinding::new(args.blinding_factor.as_bytes());
        let after_blind = Timestamp::now_utc();
        assert_ne!(blinding.to_bytes()[0], 0);

        samples.push(Sample {
            creation_time: after_create
                .duration_since(before_create)
                .whole_nanoseconds(),
            verification_time: after_verify
                .duration_since(before_verify)
                .whole_nanoseconds(),
            proving_time: after_prove.duration_since(before_prove).whole_nanoseconds(),
            open_time: after_open.duration_since(before_open).whole_nanoseconds(),
            blinding: after_blind.duration_since(before_blind).whole_nanoseconds(),
        })
    }

    println!("{}", "\n");

    // Calculate the mean
    println!("Calculating statistics");
    println!("   Mean: ");

    let count = args.count as f64;
    let mut mean = SampleStatistics::default();
    print!("      Creation time:     ");
    stdout().flush().unwrap();
    mean.creation_time = samples.iter().map(|v| v.creation_time).sum::<i128>() as f64 / count;
    print_friendly(mean.creation_time);
    print!("      Verification time: ");
    stdout().flush().unwrap();
    mean.verification_time =
        samples.iter().map(|v| v.verification_time).sum::<i128>() as f64 / count;
    print_friendly(mean.verification_time);
    print!("      Proving time:      ");
    stdout().flush().unwrap();
    mean.proving_time = samples.iter().map(|v| v.proving_time).sum::<i128>() as f64 / count;
    print_friendly(mean.proving_time);
    print!("      Open time:         ");
    stdout().flush().unwrap();
    mean.open_time = samples.iter().map(|v| v.open_time).sum::<i128>() as f64 / count;
    print_friendly(mean.open_time);
    print!("      Blinding time:     ");
    stdout().flush().unwrap();
    mean.blinding = samples.iter().map(|v| v.blinding).sum::<i128>() as f64 / count;
    print_friendly(mean.blinding);

    println!("   Standard deviation");
    let mut std_dev = SampleStatistics::default();
    print!("      Creation time:     ");
    stdout().flush().unwrap();
    std_dev.creation_time = {
        let variance = samples
            .iter()
            .map(|s| {
                let diff = mean.creation_time - (s.creation_time as f64);
                diff * diff
            })
            .sum::<f64>()
            / count;
        variance.sqrt()
    };
    print_friendly(std_dev.creation_time);
    print!("      Verification time: ");
    stdout().flush().unwrap();
    std_dev.verification_time = {
        let variance = samples
            .iter()
            .map(|s| {
                let diff = mean.verification_time - (s.verification_time as f64);
                diff * diff
            })
            .sum::<f64>()
            / count;
        variance.sqrt()
    };
    print_friendly(std_dev.verification_time);
    print!("      Proving time:      ");
    stdout().flush().unwrap();
    std_dev.proving_time = {
        let variance = samples
            .iter()
            .map(|s| {
                let diff = mean.proving_time - (s.proving_time as f64);
                diff * diff
            })
            .sum::<f64>()
            / count;
        variance.sqrt()
    };
    print_friendly(std_dev.proving_time);
    print!("      Open time:         ");
    stdout().flush().unwrap();
    std_dev.open_time = {
        let variance = samples
            .iter()
            .map(|s| {
                let diff = mean.open_time - (s.open_time as f64);
                diff * diff
            })
            .sum::<f64>()
            / count;
        variance.sqrt()
    };
    print_friendly(std_dev.open_time);
    print!("      Blinding time:     ");
    stdout().flush().unwrap();
    std_dev.blinding = {
        let variance = samples
            .iter()
            .map(|s| {
                let diff = mean.blinding - (s.blinding as f64);
                diff * diff
            })
            .sum::<f64>()
            / count;
        variance.sqrt()
    };
    print_friendly(std_dev.blinding);

    // let mut zscore = SampleStatistics::default();
    // let rnd_index = (OsRng.next_u64() % args.count) as usize;
    // println!("   Z-score for samples at index {}", rnd_index);
    // zscore.creation_time =
    //     (samples[rnd_index].creation_time as f64 - mean.creation_time) / std_dev.creation_time;
    // print!(
    //     "      Creation time     (with value {}) is ",
    //     samples[rnd_index].creation_time
    // );
    // print_friendly(zscore.creation_time);
    // zscore.verification_time = (samples[rnd_index].verification_time as f64
    //     - mean.verification_time)
    //     / std_dev.verification_time;
    // print!(
    //     "      Verification time (with value {}) is ",
    //     samples[rnd_index].verification_time
    // );
    // print_friendly(zscore.verification_time);
    // zscore.proving_time =
    //     (samples[rnd_index].proving_time as f64 - mean.proving_time) / std_dev.proving_time;
    // print!(
    //     "      Proving time      (with value {}) is ",
    //     samples[rnd_index].proving_time
    // );
    // print_friendly(zscore.proving_time);
    // zscore.open_time = (samples[rnd_index].open_time as f64 - mean.open_time) / std_dev.open_time;
    // print!(
    //     "      Open time         (with value {}) is {:?} ",
    //     samples[rnd_index].open_time, zscore.open_time,
    // );
    // print_friendly(zscore.open_time);
    // zscore.blinding = (samples[rnd_index].blinding as f64 - mean.blinding) / std_dev.blinding;
    // print!(
    //     "      Blinding time     (with value {}) is ",
    //     samples[rnd_index].blinding
    // );
    // print_friendly(zscore.blinding);

    let zscore = SampleStatistics {
        creation_time: 1.96,
        verification_time: 1.96,
        proving_time: 1.96,
        open_time: 1.96,
        blinding: 1.96,
    };

    let sqr_count = count.sqrt();
    let mut confidence_interval = SampleStatistics::default();
    println!("   Confidence-Interval");
    confidence_interval.creation_time = (zscore.creation_time * std_dev.creation_time) / sqr_count;
    println!(
        "      Creation time       + {}, - {}",
        human_friendly(confidence_interval.creation_time),
        human_friendly(confidence_interval.creation_time)
    );
    confidence_interval.verification_time =
        (zscore.verification_time * std_dev.verification_time) / sqr_count;
    println!(
        "      Verification time   + {}, - {}",
        human_friendly(confidence_interval.verification_time),
        human_friendly(confidence_interval.verification_time)
    );
    confidence_interval.proving_time = (zscore.proving_time * std_dev.proving_time) / sqr_count;
    println!(
        "      Proving time        + {}, - {}",
        human_friendly(confidence_interval.proving_time),
        human_friendly(confidence_interval.proving_time)
    );
    confidence_interval.open_time = (zscore.open_time * std_dev.open_time) / sqr_count;
    println!(
        "      Open time           + {}, - {}",
        human_friendly(confidence_interval.open_time),
        human_friendly(confidence_interval.open_time)
    );
    confidence_interval.blinding = (zscore.blinding * std_dev.blinding) / sqr_count;
    println!(
        "      Blinding time       + {}, - {}",
        human_friendly(confidence_interval.blinding),
        human_friendly(confidence_interval.blinding)
    );
}

fn print_friendly(stat: f64) {
    let stat = stat as i128;
    let len = stat.to_string().len();
    match len {
        1 | 2 | 3 => println!("{} ns", stat),
        4 | 5 | 6 => println!("{} {}s", stat / 1_000, std::char::from_u32(0x00B5).unwrap()),
        7 | 8 | 9 => println!("{} ms", stat / 1_000_000),
        n => println!("{} s", n / 1_000_000_000)
    }
}

fn human_friendly(stat: f64) -> String {
    let stat = stat as i128;
    let len = stat.to_string().len();
    let mut output = Vec::<u8>::new();
    match len {
        1 | 2 | 3 => write!(output, "{} ns", stat).unwrap(),
        4 | 5 | 6 => write!(output, "{} {}s", stat / 1_000, std::char::from_u32(0x00B5).unwrap()).unwrap(),
        7 | 8 | 9 => write!(output, "{} ms", stat / 1_000_000).unwrap(),
        n => write!(output, "{} s", n / 1_000_000_000).unwrap()
    }
    String::from_utf8(output).unwrap()
}