use clap::Parser;
use iso8601_timestamp::Timestamp;
use oberon::*;
use rand_core::{OsRng, RngCore, CryptoRng, SeedableRng, Error};
use rand_chacha::ChaChaRng;
use rand_xorshift::XorShiftRng;
use statrs::{
    distribution::{FisherSnedecor, ContinuousCDF},
    statistics::Statistics,
};
use std::io::{stdout, Write};
use uuid::Uuid;

struct CsXorShiftRng {
    rng: XorShiftRng,
}

impl CryptoRng for CsXorShiftRng {}

impl SeedableRng for CsXorShiftRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self { rng: XorShiftRng::from_seed(seed) }
    }
}

impl RngCore for CsXorShiftRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CsXorShiftRng {
    pub fn from_entropy() -> Self {
        Self { rng: XorShiftRng::from_entropy() }
    }
}

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
    pub proving_time_osrng: i128,
    pub proving_time_chacha: i128,
    pub proving_time_xorshift: i128,
    pub open_time: i128,
    pub blinding: i128,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SampleStatistics {
    pub creation_time: f64,
    pub verification_time: f64,
    pub proving_time_osrng: f64,
    pub proving_time_chacha: f64,
    pub proving_time_xorshift: f64,
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

    let mut chacha_rng = ChaChaRng::from_entropy();
    let mut xorshift_rng = CsXorShiftRng::from_entropy();

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

        let before_prove_chacha = Timestamp::now_utc();
        let proof_chacha = Proof::new(&token, &[], id_bytes, &nonce, &mut chacha_rng);
        let after_prove_chacha = Timestamp::now_utc();
        assert!(proof_chacha.is_some());


        let before_prove_xorshift = Timestamp::now_utc();
        let proof_xorshift = Proof::new(&token, &[], id_bytes, &nonce, &mut xorshift_rng);
        let after_prove_xorshift = Timestamp::now_utc();
        assert!(proof_xorshift.is_some());

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
            proving_time_osrng: after_prove.duration_since(before_prove).whole_nanoseconds(),
            proving_time_chacha: after_prove_chacha.duration_since(before_prove_chacha).whole_nanoseconds(),
            proving_time_xorshift: after_prove_xorshift.duration_since(before_prove_xorshift).whole_nanoseconds(),
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
    mean.proving_time_osrng = samples.iter().map(|v| v.proving_time_osrng).sum::<i128>() as f64 / count;
    print_friendly(mean.proving_time_osrng);

    print!("      Proving time CA    ");
    stdout().flush().unwrap();
    mean.proving_time_chacha = samples.iter().map(|v| v.proving_time_chacha).sum::<i128>() as f64 / count;
    print_friendly(mean.proving_time_chacha);


    print!("      Proving time XOR   ");
    stdout().flush().unwrap();
    mean.proving_time_xorshift = samples.iter().map(|v| v.proving_time_xorshift).sum::<i128>() as f64 / count;
    print_friendly(mean.proving_time_xorshift);

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
    std_dev.proving_time_osrng = {
        let variance = samples
            .iter()
            .map(|s| {
                let diff = mean.proving_time_osrng - (s.proving_time_osrng as f64);
                diff * diff
            })
            .sum::<f64>()
            / count;
        variance.sqrt()
    };
    print_friendly(std_dev.proving_time_osrng);

    print!("      Proving time CA:   ");
    stdout().flush().unwrap();
    std_dev.proving_time_chacha = {
        let variance = samples
            .iter()
            .map(|s| {
                let diff = mean.proving_time_chacha - (s.proving_time_chacha as f64);
                diff * diff
            })
            .sum::<f64>()
            / count;
        variance.sqrt()
    };
    print_friendly(std_dev.proving_time_chacha);

    print!("      Proving time XOR:  ");
    stdout().flush().unwrap();
    std_dev.proving_time_xorshift = {
        let variance = samples
            .iter()
            .map(|s| {
                let diff = mean.proving_time_xorshift - (s.proving_time_xorshift as f64);
                diff * diff
            })
            .sum::<f64>()
            / count;
        variance.sqrt()
    };
    print_friendly(std_dev.proving_time_xorshift);

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

    let zscore = SampleStatistics {
        creation_time: 1.96,
        verification_time: 1.96,
        proving_time_osrng: 1.96,
        proving_time_chacha: 1.96,
        proving_time_xorshift: 1.96,
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
    confidence_interval.proving_time_osrng = (zscore.proving_time_osrng * std_dev.proving_time_osrng) / sqr_count;
    println!(
        "      Proving time        + {}, - {}",
        human_friendly(confidence_interval.proving_time_osrng),
        human_friendly(confidence_interval.proving_time_osrng)
    );

    confidence_interval.proving_time_chacha = (zscore.proving_time_chacha * std_dev.proving_time_chacha) / sqr_count;
    println!(
        "      Proving time CA     + {}, - {}",
        human_friendly(confidence_interval.proving_time_chacha),
        human_friendly(confidence_interval.proving_time_chacha)
    );

    confidence_interval.proving_time_xorshift = (zscore.proving_time_xorshift * std_dev.proving_time_xorshift) / sqr_count;
    println!(
        "      Proving time XOR    + {}, - {}",
        human_friendly(confidence_interval.proving_time_xorshift),
        human_friendly(confidence_interval.proving_time_xorshift)
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

    // Compute ANOVA
    // 3 populations
    let k = 3usize;
    let n = (args.count * 3) as usize;
    let means = [mean.proving_time_osrng, mean.proving_time_chacha, mean.proving_time_xorshift];
    let grand_mean = means.mean();

    let ss_between = means
        .iter()
        .map(| m| {
            count * (m - grand_mean).powi(2)
        })
        .sum::<f64>();

    let osrng = samples.iter().map(|s| s.proving_time_osrng as f64).collect::<Vec<f64>>();
    let chacha = samples.iter().map(|s| s.proving_time_chacha as f64).collect::<Vec<f64>>();
    let xorshift = samples.iter().map(|s| s.proving_time_xorshift as f64).collect::<Vec<f64>>();

    let data = vec![osrng, chacha, xorshift];

    let ss_within = data
        .iter()
        .enumerate()
        .map(|(i, g)| sso(g, means[i]) - count * (means[i] - grand_mean).powi(2))
        .sum::<f64>();

    let df_between = k - 1;
    let df_within = n - k;

    let ms_between = ss_between / (df_between as f64);
    let ms_within = ss_within / (df_within as f64);

    let f_value = ms_between / ms_within;

    let f_dist = FisherSnedecor::new(df_between as f64, df_within as f64).unwrap();
    let p_value = 1.0 - f_dist.cdf(f_value);

    println!("   F-value: {:.3}", f_value);
    println!("   p-value: {:.3}", p_value);
}

fn print_friendly(s: f64) {
    let stat = s as i128;
    let len = stat.to_string().len();
    match len {
        1 | 2 | 3 => println!("{:.3} ns", s),
        4 | 5 | 6 => println!("{:.3} {}s", s/ 1_000.0, std::char::from_u32(0x00B5).unwrap()),
        7 | 8 | 9 => println!("{:.3} ms", s/ 1_000_000.0),
        _ => println!("{:.3} s", s / 1_000_000_000.0)
    }
}

fn human_friendly(s: f64) -> String {
    let stat = s as i128;
    let len = stat.to_string().len();
    let mut output = Vec::<u8>::new();
    match len {
        1 | 2 | 3 => write!(output, "{:.3} ns", s).unwrap(),
        4 | 5 | 6 => write!(output, "{:.3} {}s", s / 1_000.0, std::char::from_u32(0x00B5).unwrap()).unwrap(),
        7 | 8 | 9 => write!(output, "{:.3} ms", s / 1_000_000.0).unwrap(),
        _ => write!(output, "{:.3} s", s / 1_000_000_000.0).unwrap()
    }
    String::from_utf8(output).unwrap()
}

fn sso(group: &[f64], mean: f64) -> f64 {
    group.iter().map(|x| (x - mean).powi(2)).sum()
}