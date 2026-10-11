//! Every supported hash algorithm behind one interface.
//!
//! Pick an [`Algorithm`], then hash a file with [`hash_file`], a reader
//! with [`hash_reader`], or feed data to a [`Hasher`] yourself, for example
//! to report progress while hashing a large file.
//!
//! ```
//! use kryptor::hash::{self, Algorithm};
//!
//! let digest = hash::hash_reader(Algorithm::Sha256, &b"abc"[..])?;
//! assert_eq!(
//!     digest.to_string(),
//!     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
//! );
//! # Ok::<(), std::io::Error>(())
//! ```

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use digest::Digest as _;

/// Read buffer size for [`hash_reader`]. Large reads let BLAKE3 use its
/// widest SIMD paths.
const READ_BUF_LEN: usize = 64 * 1024;

/// A supported hash algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// MD5. Broken: only for checking legacy checksums.
    Md5,
    /// SHA-1. Broken: only for checking legacy checksums.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    #[default]
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/224 (SHA-512 truncated to 224 bits).
    Sha512_224,
    /// SHA-512/256 (SHA-512 truncated to 256 bits).
    Sha512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// BLAKE2b with a 512-bit digest.
    Blake2b512,
    /// BLAKE2s with a 256-bit digest.
    Blake2s256,
    /// BLAKE3 with its default 256-bit digest.
    Blake3,
}

impl Algorithm {
    /// Every supported algorithm, in the order they should be shown to users.
    pub const ALL: &'static [Self] = &[
        Self::Md5,
        Self::Sha1,
        Self::Sha224,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Sha512_224,
        Self::Sha512_256,
        Self::Sha3_224,
        Self::Sha3_256,
        Self::Sha3_384,
        Self::Sha3_512,
        Self::Blake2b512,
        Self::Blake2s256,
        Self::Blake3,
    ];

    /// Returns the identifier users type to select this algorithm, e.g.
    /// `"sha3-256"`. The inverse of [`Algorithm::from_name`].
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha512_224 => "sha512-224",
            Self::Sha512_256 => "sha512-256",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
            Self::Blake2b512 => "blake2b-512",
            Self::Blake2s256 => "blake2s-256",
            Self::Blake3 => "blake3",
        }
    }

    /// Looks up an algorithm by its [`name`](Self::name). Matching is exact
    /// and case-sensitive.
    ///
    /// ```
    /// use kryptor::hash::Algorithm;
    ///
    /// assert_eq!(Algorithm::from_name("sha3-256"), Some(Algorithm::Sha3_256));
    /// assert_eq!(Algorithm::from_name("SHA3-256"), None);
    /// ```
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|algorithm| algorithm.name() == name)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Incrementally computes a [`Digest`] with one [`Algorithm`].
///
/// Use this instead of [`hash_reader`] when you need to own the read loop,
/// e.g. to report progress or support cancellation. It also implements
/// [`Write`], so it can be the destination of [`io::copy`].
///
/// ```
/// use kryptor::hash::{Algorithm, Hasher};
///
/// let mut hasher = Hasher::new(Algorithm::Blake3);
/// hasher.update(b"a");
/// hasher.update(b"bc");
/// assert_eq!(
///     hasher.finalize().to_string(),
///     "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
/// );
/// ```
#[derive(Clone)]
pub struct Hasher {
    algorithm: Algorithm,
    state: State,
}

/// The backend hasher for each [`Algorithm`], kept private so callers never
/// depend on the backend crates.
#[derive(Clone)]
enum State {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha512_224(sha2::Sha512_224),
    Sha512_256(sha2::Sha512_256),
    Sha3_224(sha3::Sha3_224),
    Sha3_256(sha3::Sha3_256),
    Sha3_384(sha3::Sha3_384),
    Sha3_512(sha3::Sha3_512),
    Blake2b512(blake2::Blake2b512),
    Blake2s256(blake2::Blake2s256),
    // Boxed because `blake3::Hasher` is ~1.9 KB, several times larger than
    // every other variant.
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    /// Creates a hasher for `algorithm`.
    pub fn new(algorithm: Algorithm) -> Self {
        let state = match algorithm {
            Algorithm::Md5 => State::Md5(Default::default()),
            Algorithm::Sha1 => State::Sha1(Default::default()),
            Algorithm::Sha224 => State::Sha224(Default::default()),
            Algorithm::Sha256 => State::Sha256(Default::default()),
            Algorithm::Sha384 => State::Sha384(Default::default()),
            Algorithm::Sha512 => State::Sha512(Default::default()),
            Algorithm::Sha512_224 => State::Sha512_224(Default::default()),
            Algorithm::Sha512_256 => State::Sha512_256(Default::default()),
            Algorithm::Sha3_224 => State::Sha3_224(Default::default()),
            Algorithm::Sha3_256 => State::Sha3_256(Default::default()),
            Algorithm::Sha3_384 => State::Sha3_384(Default::default()),
            Algorithm::Sha3_512 => State::Sha3_512(Default::default()),
            Algorithm::Blake2b512 => State::Blake2b512(Default::default()),
            Algorithm::Blake2s256 => State::Blake2s256(Default::default()),
            Algorithm::Blake3 => State::Blake3(Default::default()),
        };
        Self { algorithm, state }
    }

    /// Feeds `data` into the hash. Several calls give the same digest as
    /// one call with the data concatenated.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            State::Md5(h) => h.update(data),
            State::Sha1(h) => h.update(data),
            State::Sha224(h) => h.update(data),
            State::Sha256(h) => h.update(data),
            State::Sha384(h) => h.update(data),
            State::Sha512(h) => h.update(data),
            State::Sha512_224(h) => h.update(data),
            State::Sha512_256(h) => h.update(data),
            State::Sha3_224(h) => h.update(data),
            State::Sha3_256(h) => h.update(data),
            State::Sha3_384(h) => h.update(data),
            State::Sha3_512(h) => h.update(data),
            State::Blake2b512(h) => h.update(data),
            State::Blake2s256(h) => h.update(data),
            State::Blake3(h) => {
                h.update(data);
            }
        }
    }

    /// Consumes the hasher and returns the digest of everything fed to it.
    pub fn finalize(self) -> Digest {
        let bytes: Box<[u8]> = match self.state {
            State::Md5(h) => h.finalize().as_slice().into(),
            State::Sha1(h) => h.finalize().as_slice().into(),
            State::Sha224(h) => h.finalize().as_slice().into(),
            State::Sha256(h) => h.finalize().as_slice().into(),
            State::Sha384(h) => h.finalize().as_slice().into(),
            State::Sha512(h) => h.finalize().as_slice().into(),
            State::Sha512_224(h) => h.finalize().as_slice().into(),
            State::Sha512_256(h) => h.finalize().as_slice().into(),
            State::Sha3_224(h) => h.finalize().as_slice().into(),
            State::Sha3_256(h) => h.finalize().as_slice().into(),
            State::Sha3_384(h) => h.finalize().as_slice().into(),
            State::Sha3_512(h) => h.finalize().as_slice().into(),
            State::Blake2b512(h) => h.finalize().as_slice().into(),
            State::Blake2s256(h) => h.finalize().as_slice().into(),
            State::Blake3(h) => h.finalize().as_bytes().as_slice().into(),
        };
        Digest(bytes)
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hasher")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Writing to a `Hasher` feeds it data and never fails.
impl Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The output of a hash function. Displays as lowercase hex.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Digest(Box<[u8]>);

impl Digest {
    /// Returns the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

/// Hashes everything `reader` yields until EOF.
///
/// Reads are buffered internally, so pass the reader as-is (e.g. a
/// [`File`](std::fs::File)) rather than wrapping it in a [`BufReader`].
///
/// # Errors
///
/// Returns the first I/O error from `reader`. [`io::ErrorKind::Interrupted`]
/// is retried, not returned.
// `skip_all`: spans record only the fields listed, never arguments wholesale,
// so nothing secret ends up in logs by accident.
#[tracing::instrument(skip_all, fields(%algorithm))]
pub fn hash_reader<R: Read>(algorithm: Algorithm, reader: R) -> io::Result<Digest> {
    let started = Instant::now();
    let mut hasher = Hasher::new(algorithm);
    let bytes = io::copy(
        &mut BufReader::with_capacity(READ_BUF_LEN, reader),
        &mut hasher,
    )?;
    tracing::info!(bytes, elapsed = ?started.elapsed(), "finished hashing");
    Ok(hasher.finalize())
}

/// Hashes the contents of the file at `path`.
///
/// ```no_run
/// use kryptor::hash::{self, Algorithm};
///
/// let digest = hash::hash_file(Algorithm::Blake3, "ubuntu.iso")?;
/// println!("{digest}");
/// # Ok::<(), kryptor::hash::HashFileError>(())
/// ```
///
/// # Errors
///
/// Returns [`HashFileError`] if the file can't be opened or read.
#[tracing::instrument(skip_all, fields(path = %path.as_ref().display()))]
pub fn hash_file(algorithm: Algorithm, path: impl AsRef<Path>) -> Result<Digest, HashFileError> {
    let path = path.as_ref();
    File::open(path)
        .and_then(|file| hash_reader(algorithm, file))
        .map_err(|source| HashFileError {
            path: path.to_owned(),
            source,
        })
}

/// A file couldn't be hashed because opening or reading it failed.
///
/// The message names the file. The underlying [`io::Error`] is the
/// [`source`](std::error::Error::source), not part of the message, so error
/// reporters don't print it twice.
#[derive(Debug, thiserror::Error)]
#[error("cannot read {}", .path.display())]
pub struct HashFileError {
    path: PathBuf,
    source: io::Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{self, Read};

    /// `(name, digest of "", digest of "abc")` for every algorithm.
    ///
    /// Computed with Python's `hashlib`, except BLAKE3, which comes from the
    /// published test vectors.
    const KNOWN_ANSWERS: &[(&str, &str, &str)] = &[
        (
            "md5",
            "d41d8cd98f00b204e9800998ecf8427e",
            "900150983cd24fb0d6963f7d28e17f72",
        ),
        (
            "sha1",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        ),
        (
            "sha224",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        ),
        (
            "sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "sha384",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            "sha512",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            "sha512-224",
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
        ),
        (
            "sha512-256",
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        ),
        (
            "sha3-224",
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
        ),
        (
            "sha3-256",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        ),
        (
            "sha3-384",
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
        ),
        (
            "sha3-512",
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        ),
        (
            "blake2b-512",
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        ),
        (
            "blake2s-256",
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
        ),
        (
            "blake3",
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        ),
    ];

    fn hash(algorithm: Algorithm, data: &[u8]) -> String {
        let mut hasher = Hasher::new(algorithm);
        hasher.update(data);
        hasher.finalize().to_string()
    }

    #[test]
    fn every_algorithm_has_a_known_answer() {
        // Each entry resolves to a distinct algorithm (they all hash
        // differently), so matching lengths means no algorithm is missing.
        assert_eq!(KNOWN_ANSWERS.len(), Algorithm::ALL.len());
    }

    #[test]
    fn known_answers() {
        for &(name, empty, abc) in KNOWN_ANSWERS {
            let algorithm = Algorithm::from_name(name)
                .unwrap_or_else(|| panic!("{name:?} should be a known algorithm"));

            assert_eq!(hash(algorithm, b""), empty, "{name}(\"\")");
            assert_eq!(hash(algorithm, b"abc"), abc, "{name}(\"abc\")");
        }
    }

    #[test]
    fn names_round_trip() {
        for &algorithm in Algorithm::ALL {
            assert_eq!(Algorithm::from_name(algorithm.name()), Some(algorithm));
            assert_eq!(algorithm.to_string(), algorithm.name());
        }
    }

    #[test]
    fn unknown_names_are_rejected() {
        for name in ["", "md4", "sha", "sha-256", "SHA256", "sha256 "] {
            assert_eq!(Algorithm::from_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn sha256_multi_block_messages() {
        let vectors = [
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];

        for (input, expected) in vectors {
            assert_eq!(
                hash(Algorithm::Sha256, input.as_bytes()),
                expected,
                "{input:?}"
            );
        }
    }

    #[test]
    fn split_updates_match_a_single_update() {
        let mut hasher = Hasher::new(Algorithm::Sha256);
        for chunk in [&b"a"[..], b"", b"bc"] {
            hasher.update(chunk);
        }

        assert_eq!(
            hasher.finalize().to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digest_bytes_are_raw_not_hex() {
        let mut hasher = Hasher::new(Algorithm::Md5);
        hasher.update(b"abc");
        let digest = hasher.finalize();

        assert_eq!(
            digest.as_bytes(),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
    }

    /// Returns one byte per read, with an `Interrupted` error before each.
    struct TrickleReader {
        data: &'static [u8],
        interrupt_next: bool,
    }

    impl Read for TrickleReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt_next = !self.interrupt_next;
            if self.interrupt_next {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let Some((&first, rest)) = self.data.split_first() else {
                return Ok(0);
            };
            buf[0] = first;
            self.data = rest;
            Ok(1)
        }
    }

    #[test]
    fn hash_reader_handles_short_and_interrupted_reads() {
        let reader = TrickleReader {
            data: b"abc",
            interrupt_next: false,
        };

        let digest = hash_reader(Algorithm::Sha256, reader).expect("should hash");

        assert_eq!(
            digest.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_reader_propagates_read_errors() {
        struct DeniedReader;

        impl Read for DeniedReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }

        let err = hash_reader(Algorithm::Sha256, DeniedReader).expect_err("should fail");

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
