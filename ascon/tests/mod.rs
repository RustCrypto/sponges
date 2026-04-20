//! Basic tests

#[test]
fn ascon_permute6() {
    let mut state = [
        0x0123456789abcdef,
        0xef0123456789abcd,
        0xcdef0123456789ab,
        0xabcdef0123456789,
        0x89abcdef01234567,
    ];
    ascon::permute6(&mut state);
    assert_eq!(state[0], 0xc27b505c635eb07f);
    assert_eq!(state[1], 0xd388f5d2a72046fa);
    assert_eq!(state[2], 0x9e415c204d7b15e7);
    assert_eq!(state[3], 0xce0d71450fe44581);
    assert_eq!(state[4], 0xdd7c5fef57befe48);
}

#[test]
fn ascon_permute8() {
    let mut state = [
        0x0123456789abcdef,
        0xef0123456789abcd,
        0xcdef0123456789ab,
        0xabcdef0123456789,
        0x89abcdef01234567,
    ];
    ascon::permute8(&mut state);
    assert_eq!(state[0], 0x67ed228272f46eee);
    assert_eq!(state[1], 0x80bc0b097aad7944);
    assert_eq!(state[2], 0x2fa599382c6db215);
    assert_eq!(state[3], 0x368133fae2f7667a);
    assert_eq!(state[4], 0x28cefb195a7c651c);
}

#[test]
fn state_permute_12() {
    let mut state = [
        0x0123456789abcdef,
        0xef0123456789abcd,
        0xcdef0123456789ab,
        0xabcdef0123456789,
        0x89abcdef01234567,
    ];
    ascon::permute12(&mut state);
    assert_eq!(state[0], 0x206416dfc624bb14);
    assert_eq!(state[1], 0x1b0c47a601058aab);
    assert_eq!(state[2], 0x8934cfc93814cddd);
    assert_eq!(state[3], 0xa9738d287a748e4b);
    assert_eq!(state[4], 0xddd934f058afc7e1);
}
