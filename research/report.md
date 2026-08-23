# Genesis Puzzle — Stage A report

Generated 2026-08-23 13:06:34Z from stored facts and SQLite results. Private candidate
scalars are redacted and are not stored.

## Puzzle statement

> I made a Bitcoin puzzle using information contained in the genesis block
> created by Satoshi to generate the wallet. The entropy is extremely low. I
> didn't even need to back anything up. Everything I needed was already in the
> genesis block. Good luck!

Announcement transaction:
`b691de3657880d9a1eabd2783b1a9fa8c5313ced338495bf10e85727012d7a77`,
block `963629`, publication time `2026-08-22 19:45 UTC`.

Satoshi's Genesis block is a public, narrowly scoped artifact. This researcher
asks whether any *canonical public field of that block*, taken as a secp256k1
scalar or as SHA256 of that field, produces a standard Bitcoin address that
can be compared against a later suspected puzzle output.

This is not a general private-key cracking framework. Stage B, brute force,
PBKDF2/BIP39, Metal, transaction creation, wallet import, spending, and
broadcasting are out of scope.

## Known public facts

Genesis (Bitcoin mainnet):

- version `1`
- timestamp `1231006505`
- bits `0x1d00ffff` / `486604799`
- target `00000000ffff0000000000000000000000000000000000000000000000000000`
- nonce `2083236893`
- previous hash: 32 zero bytes
- block hash (display): `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`
- block hash (wire): `6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000`
- Merkle root / coinbase txid (display): `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b`
- raw coinbase transaction: `01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000`
- coinbase scriptSig: `04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73`
- output `5000000000` sats
- headline: `The Times 03/Jan/2009 Chancellor on brink of second bailout for banks`
- Genesis pubkey: `04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f`
- height `0`

Announcement transaction (verified 2026-08-23 as public chain data):

- `suspected_puzzle_output` (suspected_not_proven): 5000 sats to `bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj` (`p2wsh`) in tx `b691de3657880d9a1eabd2783b1a9fa8c5313ced338495bf10e85727012d7a77` block 963629. Suspected puzzle output, not proven. A standard P2PKH or P2WPKH address cannot match a P2WSH output without knowing or hypothesizing the witness script.

## Verified Genesis data

The raw 285-byte Genesis block is parsed, not copied field-by-field. Independent
proofs that must hold after parse:

1. `SHA256d(header)[::-1]` equals the display block hash.
2. Coinbase txid equals the known txid.
3. The one-transaction Merkle root equals the header Merkle root.
4. Headline and uncompressed pubkey match the canonical document.

`init` re-runs these proofs before any Stage A derivation.

## Hypotheses tested in Stage A

Stage A only uses canonical public values and two justified 32-byte hash
orders (wire/internal and display). It does not expand into case folding,
separators, dates, newlines, permutations, neighborhoods, repeated hashes, or
combinations (that is Stage B representation-matrix work).

What was tested, and why:

- Direct integers of nonce, timestamp, nBits, version, and reward — they are
  the obvious small public numbers printed on the block.
- Height 0 as a direct scalar — recorded and eliminated; zero is not a valid
  secp256k1 secret and is never passed to coincurve.
- SHA256 of those canonical ASCII/hex encodings, of the headline, of the raw
  header, of both justified block-hash/Merkle byte orders, and of the Genesis
  public key — a one-way fold of a public artifact into a 256-bit scalar.
- Direct 32-byte integer interpretation of the block hash and Merkle root in
  wire order and display order, where the integer falls inside `[1, n)`.

The private scalar of every derivation is redacted. SQLite stores provenance,
fingerprints, public keys, and addresses only.

## Stage A results

- status: ok
- mode: balanced
- elapsed_seconds: 0.00215729046612978
- rate_per_second: 10661.522108917692
- checkpoint: checkpoint-not-needed


- total derivations: 23
- invalid derivations: 1
- unique valid keys: 22
- duplicates (extra provenance paths onto an already-seen scalar): 0
- addresses by type:
  - uncompressed P2PKH: 22
  - compressed P2PKH: 22
  - compressed P2WPKH: 22
- known-target matches: 0
- chain-history state: checked (66 addresses)

No Stage A P2PKH/P2WPKH address equals the suspected P2WSH output. That is expected: a standard-key address cannot match a P2WSH output without knowing or hypothesizing the witness script.

### Address history

- never seen: 51
- seen but empty: 0
- currently funded: 0
- spent history: 15

Addresses with blockchain history:

- `12AKRNHpFhDSBDD9rSn74VAzZSL3774PxQ` (p2pkh_uncompressed): spent_history; derivations=A-19; transactions=182; balance=0 sats; received=21293065 sats; sent=21293065 sats
- `12PVrgcRWrd1ZCimRxW8H2iLbCiZqk5rmN` (p2pkh_uncompressed): spent_history; derivations=A-18; transactions=2; balance=0 sats; received=60000 sats; sent=60000 sats
- `14q3BEP6pvmW26CnbXAVgFjpXi9bBzJ22s` (p2pkh_uncompressed): spent_history; derivations=A-15; transactions=4; balance=0 sats; received=2505 sats; sent=2505 sats
- `164qRoL9B3oxAZCn2RS6kAFejJQyAEcjaw` (p2pkh_uncompressed): spent_history; derivations=A-16; transactions=28; balance=0 sats; received=571253 sats; sent=571253 sats
- `18Zhv4BXBdqb6GkVVwGBr5ugVYwfGkAdZN` (p2pkh_compressed): spent_history; derivations=A-11; transactions=6; balance=0 sats; received=6463 sats; sent=6463 sats
- `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` (p2pkh_compressed): spent_history; derivations=A-12; transactions=197; balance=0 sats; received=25001029 sats; sent=25001029 sats
- `1Dt8ty59tU9LkrXG2ocWeSzKFAY8fu6jga` (p2pkh_compressed): spent_history; derivations=A-19; transactions=4; balance=0 sats; received=316000 sats; sent=316000 sats
- `1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm` (p2pkh_uncompressed): spent_history; derivations=A-12; transactions=1475; balance=0 sats; received=784927386 sats; sent=784927386 sats
- `1F8oQoSGLMSouTsu94iXGjBNAt43T97dvY` (p2pkh_compressed): spent_history; derivations=A-07; transactions=4; balance=0 sats; received=11000 sats; sent=11000 sats
- `1KxUVU9DKfdaTLMnXBLS5BZRf56cFnRosk` (p2pkh_uncompressed): spent_history; derivations=A-21; transactions=6; balance=0 sats; received=516960 sats; sent=516960 sats
- `1MJp4z3ig498hNATfgHBAnLFhwoZpvw118` (p2pkh_compressed): spent_history; derivations=A-16; transactions=6; balance=0 sats; received=451752 sats; sent=451752 sats
- `1Nbm3JoDpwS4HRw9WmHaKGAzaeSKXoQ6Ej` (p2pkh_uncompressed): spent_history; derivations=A-07; transactions=24; balance=0 sats; received=3862600 sats; sent=3862600 sats
- `bc1q34x4pr6m7tpgkg9rsc6qtuza8nfhfvz93895ln` (p2wpkh): spent_history; derivations=A-19; transactions=6; balance=0 sats; received=11401 sats; sent=11401 sats
- `bc1qmmqwpsupw836pz50c87ze2l4a8xjmvr6x3ww3m` (p2wpkh): spent_history; derivations=A-16; transactions=2; balance=0 sats; received=9779 sats; sent=9779 sats
- `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` (p2wpkh): spent_history; derivations=A-12; transactions=166; balance=0 sats; received=1447883 sats; sent=1447883 sats

### Interesting observations

- 15 generated address(es) have public chain history.
- 0 are currently funded; 15
  have spent history and zero current balance.
- Public history is a research signal, not a target match. Widely known weak
  keys (for example direct scalar `1`) are expected to have unrelated test or
  sweep activity. The suspected puzzle output remains the separate P2WSH
  program recorded above.

### Derivations

- `A-01` [valid] Interpret the public Genesis header nonce as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.55)
- `A-02` [valid] Interpret the public Genesis header timestamp as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.5)
- `A-03` [valid] Interpret nBits 0x1d00ffff as a secp256k1 scalar. (source `genesis.header.bits`, transform `identity_integer`, confidence 0.45)
- `A-04` [valid] SHA256 of the ASCII decimal nonce. (source `genesis.header.nonce`, transform `sha256`, confidence 0.4)
- `A-05` [valid] SHA256 of the ASCII decimal timestamp. (source `genesis.header.timestamp`, transform `sha256`, confidence 0.4)
- `A-06` [valid] SHA256 of the canonical lowercase nBits hex without 0x. (source `genesis.header.bits`, transform `sha256`, confidence 0.4)
- `A-07` [valid] SHA256 of the exact coinbase headline UTF-8 bytes. (source `genesis.coinbase.headline`, transform `sha256`, confidence 0.5)
- `A-08` [valid] SHA256 of the raw 80-byte Genesis header (single SHA256, not SHA256d). (source `genesis.header.raw`, transform `sha256`, confidence 0.35)
- `A-09` [valid] SHA256 of the block-hash raw/wire bytes. (source `genesis.block_hash.wire`, transform `sha256`, confidence 0.3)
- `A-10` [valid] SHA256 of the Merkle-root raw/wire bytes. (source `genesis.merkle_root.wire`, transform `sha256`, confidence 0.3)
- `A-11` [valid] SHA256 of the raw 65-byte Genesis public key. (source `genesis.coinbase.pubkey`, transform `sha256`, confidence 0.3)
- `A-12` [valid] Interpret the public Genesis block version as a secp256k1 scalar. (source `genesis.header.version`, transform `identity_integer`, confidence 0.25)
- `A-13` [valid] Interpret the 50 BTC coinbase value in sats as a secp256k1 scalar. (source `genesis.tx.reward_sats`, transform `identity_integer`, confidence 0.25)
- `A-14` [eliminated] Record height 0 as an invalid/eliminated direct scalar. It is never passed to coincurve. (source `genesis.height`, transform `identity_integer`, confidence 0.05)
- `A-15` [valid] Direct scalar interpretation of the 32-byte block hash in wire/internal order. (source `genesis.block_hash.wire`, transform `identity_bytes_be`, confidence 0.2)
- `A-16` [valid] Direct scalar interpretation of the 32-byte block hash in display order. (source `genesis.block_hash.display`, transform `identity_bytes_be`, confidence 0.2)
- `A-17` [valid] Direct scalar interpretation of the 32-byte Merkle root in wire/internal order. (source `genesis.merkle_root.wire`, transform `identity_bytes_be`, confidence 0.2)
- `A-18` [valid] Direct scalar interpretation of the 32-byte Merkle root in display order. (source `genesis.merkle_root.display`, transform `identity_bytes_be`, confidence 0.2)
- `A-19` [valid] SHA256 of the canonical ASCII decimal version. (source `genesis.header.version`, transform `sha256`, confidence 0.25)
- `A-20` [valid] SHA256 of the canonical ASCII decimal reward in sats. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.25)
- `A-21` [valid] SHA256 of the canonical ASCII decimal height. (source `genesis.height`, transform `sha256`, confidence 0.2)
- `A-22` [valid] SHA256 of the block-hash display-order bytes. (source `genesis.block_hash.display`, transform `sha256`, confidence 0.19)
- `A-23` [valid] SHA256 of the Merkle-root display-order bytes. (source `genesis.merkle_root.display`, transform `sha256`, confidence 0.19)

### Eliminated hypotheses

- `A-14`: height_zero_invalid_direct_scalar

### Remaining hypotheses

Stage A public-key hypotheses remain open unless their public address history
or the suspected target script provides evidence. Remaining valid derivation
ids: `A-01`, `A-02`, `A-03`, `A-04`, `A-05`, `A-06`, `A-07`, `A-08`, `A-09`, `A-10`, `A-11`, `A-12`, `A-13`, `A-15`, `A-16`, `A-17`, `A-18`, `A-19`, `A-20`, `A-21`, `A-22`, `A-23`.

They are not claims of a match. They are simply scalars that produced standard
P2PKH/P2WPKH addresses which do not, by themselves, test a P2WSH output.

## P2WSH gap

The suspected target is P2WSH (`bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj`).
Standard P2PKH and P2WPKH derivations from Stage A public keys cannot directly
test its unknown witness script. A HASH160(pubkey) is the wrong program length
and the wrong script template compared with SHA256(witnessScript).

## Next highest-value Stage B experiment (not executed)

Hypothesis, not a claim: before expanding a full representation matrix, test a
narrowly bounded set of *canonical single-key witness-script templates* built
from the Stage A compressed public keys, especially:

    <compressed pubkey> OP_CHECKSIG

That preserves the Genesis P2PK motif (a single key immediately followed by
CHECKSIG) inside a P2WSH program. Compare `SHA256(witnessScript)` against the
suspected 32-byte witness program
`4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833`.

Do not execute that experiment in Milestone 1. Do not brute-force, do not
search neighborhoods, and do not treat a template miss as proof that no
puzzle exists.

## Resource and safety notes

- Balanced mode is the default. Stage A is sequential.
- Pause/resume/checkpointing are future bounded-search features and are not
  needed here (`checkpoint-not-needed`).
- GPU is disabled. No temperature is measured.
- Offline is the default. Remote history checks are explicit, batched, and
  send derived public addresses only.

## Public verification sources

- Bitcoin Core's `src/kernel/chainparams.cpp` for the canonical Genesis
  construction and asserted block/Merkle hashes:
  https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp
- Raw Genesis block independently fetched from:
  https://blockchain.info/rawblock/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f?format=hex
- Announcement transaction and output facts independently fetched from:
  https://mempool.space/tx/b691de3657880d9a1eabd2783b1a9fa8c5313ced338495bf10e85727012d7a77
- P2WSH semantics (`SHA256(witnessScript)` equals the 32-byte witness program):
  https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
