#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]

/// Compute round constant
#[inline(always)]
const fn round_constant(round: u64) -> u64 {
    ((0xFu64 - round) << 4) | round
}

/// Maximum number of rounds supported by the Ascon permutation.
const MAX_ROUNDS: usize = 12;

/// Ascon's permutation state
pub type State = [u64; 5];

/// Ascon's round function
#[inline(always)]
const fn round(x: [u64; 5], c: u64) -> [u64; 5] {
    let (mut x0, mut x1, mut x3, mut x4) = (x[0], x[1], x[3], x[4]);

    // Addition of Constants
    let mut x2 = x[2] ^ c;

    // Substitution Layer.
    // BGC Optimized Implementations from:
    // Optimizing S-box Implementations Using SAT Solvers: Revisited
    // https://eprint.iacr.org/2023/1721.pdf
    let t0 = x0 ^ x4;
    let t1 = !x4;
    let t2 = t1 | x3;
    let t3 = x1 ^ x2;
    let t4 = x3 ^ x2;
    let t5 = x3 ^ x4;
    let t6 = t0 | x1;
    let t7 = x0 | t5;
    let t8 = t4 | t3;
    x1 = t0 ^ t8;
    x3 = t3 ^ t7;
    let t11 = x2 & t3;
    let t12 = t6 ^ t5;
    x2 = t3 ^ t2;
    x0 = t12 ^ t11;
    x4 = t0 ^ t12;

    // Linear Diffusion Layer
    [
        x0 ^ x0.rotate_right(19) ^ x0.rotate_right(28),
        x1 ^ x1.rotate_right(61) ^ x1.rotate_right(39),
        x2 ^ x2.rotate_right(1) ^ x2.rotate_right(6),
        x3 ^ x3.rotate_right(10) ^ x3.rotate_right(17),
        x4 ^ x4.rotate_right(7) ^ x4.rotate_right(41),
    ]
}

/// Apply Ascon permutation with the given number of rounds.
///
/// Results in a compilation error if `ROUNDS` is greater than 12.
pub const fn permute<const ROUNDS: usize>(state: &mut State) {
    const { assert!(ROUNDS <= MAX_ROUNDS) };
    let mut x = *state;

    #[cfg(not(ascon_backend = "soft-compact"))]
    {
        macro_rules! unroll_round {
            ($state:ident, $round:literal, $rounds:expr) => {
                if $round >= MAX_ROUNDS - $rounds {
                    let rc = round_constant($round);
                    $state = round($state, rc);
                }
            };
        }

        unroll_round!(x, 0, ROUNDS);
        unroll_round!(x, 1, ROUNDS);
        unroll_round!(x, 2, ROUNDS);
        unroll_round!(x, 3, ROUNDS);
        unroll_round!(x, 4, ROUNDS);
        unroll_round!(x, 5, ROUNDS);
        unroll_round!(x, 6, ROUNDS);
        unroll_round!(x, 7, ROUNDS);
        unroll_round!(x, 8, ROUNDS);
        unroll_round!(x, 9, ROUNDS);
        unroll_round!(x, 10, ROUNDS);
        unroll_round!(x, 11, ROUNDS);
    }

    #[cfg(ascon_backend = "soft-compact")]
    {
        let mut i = MAX_ROUNDS - ROUNDS;
        while i < MAX_ROUNDS {
            x = round(x, round_constant(i as u64));
            i += 1;
        }
    }

    *state = x;
}

/// Apply Ascon permutation with 12 rounds.
pub const fn permute12(state: &mut State) {
    permute::<12>(state);
}

/// Apply Ascon permutation with 8 rounds.
pub const fn permute8(state: &mut State) {
    permute::<8>(state);
}

/// Apply Ascon permutation with 6 rounds.
pub const fn permute6(state: &mut State) {
    permute::<6>(state);
}

/// Apply Ascon permutation with 1 round.
pub const fn permute1(state: &mut State) {
    permute::<1>(state);
}
