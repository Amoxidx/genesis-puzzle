# Genesis Puzzle — Stage A+B+C+D report

Generated 2026-08-24 08:46:43Z from stored facts and SQLite results. Private candidate
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
scalar or as SHA256 of that field, produces a standard Bitcoin address or a
generic single-key P2WSH program that can be compared against a later suspected
puzzle output.

This is not a general private-key cracking framework. Deterministic Stages A, B, C, and D are implemented. Stage E, brute force, PBKDF2/BIP39, Metal, transaction creation, wallet import, spending, and broadcasting are out of scope.

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

`init` re-runs these proofs before any Stage A, Stage B, Stage C, or Stage D derivation.

## Hypotheses tested in Stage A

Stage A only uses canonical public values and two justified 32-byte hash
orders (wire/internal and display). It does not expand into case folding,
separators, dates, newlines, permutations, neighborhoods, repeated hashes, or
combinations.

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

Stage A run:
- status: ok
- mode: balanced
- elapsed_seconds: 0.00215729046612978
- rate_per_second: 10661.522108917692
- checkpoint: checkpoint-not-needed

- Stage A derivations: 23
- Stage A invalid derivations: 1
- Stage A unique valid keys: 22
- Stage A duplicate provenance paths: 0
- cumulative unique valid keys after Stage A: 22
- cumulative duplicate provenance paths after Stage A: 0
- addresses by type:
  - uncompressed P2PKH: 22
  - compressed P2PKH: 22
  - compressed P2WPKH: 22
- known-target address matches: 0
- chain-history state: checked (66 addresses)

No Stage A P2PKH/P2WPKH address equals the suspected P2WSH output. That is expected: a standard-key address cannot match a P2WSH output without knowing or hypothesizing the witness script.

### Address history

Stage A derived 66 standard addresses (22 unique keys times three types).
History below is that Stage A address snapshot. Direct P2WSH comparison in
Stage B uses `SHA256(witnessScript)` against the 32-byte witness program and
does not need a blockchain-history lookup.

- never seen: 51
- seen but empty: 0
- currently funded: 0
- spent history: 15

Addresses with blockchain history:

- `12AKRNHpFhDSBDD9rSn74VAzZSL3774PxQ` (p2pkh_uncompressed): spent_history; derivations=A-19,B-029; transactions=182; balance=0 sats; received=21293065 sats; sent=21293065 sats
- `12PVrgcRWrd1ZCimRxW8H2iLbCiZqk5rmN` (p2pkh_uncompressed): spent_history; derivations=A-18; transactions=2; balance=0 sats; received=60000 sats; sent=60000 sats
- `14q3BEP6pvmW26CnbXAVgFjpXi9bBzJ22s` (p2pkh_uncompressed): spent_history; derivations=A-15; transactions=4; balance=0 sats; received=2505 sats; sent=2505 sats
- `164qRoL9B3oxAZCn2RS6kAFejJQyAEcjaw` (p2pkh_uncompressed): spent_history; derivations=A-16; transactions=28; balance=0 sats; received=571253 sats; sent=571253 sats
- `18Zhv4BXBdqb6GkVVwGBr5ugVYwfGkAdZN` (p2pkh_compressed): spent_history; derivations=A-11,B-093; transactions=6; balance=0 sats; received=6463 sats; sent=6463 sats
- `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` (p2pkh_compressed): spent_history; derivations=A-12,B-035; transactions=197; balance=0 sats; received=25001029 sats; sent=25001029 sats
- `1Dt8ty59tU9LkrXG2ocWeSzKFAY8fu6jga` (p2pkh_compressed): spent_history; derivations=A-19,B-029; transactions=4; balance=0 sats; received=316000 sats; sent=316000 sats
- `1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm` (p2pkh_uncompressed): spent_history; derivations=A-12,B-035; transactions=1475; balance=0 sats; received=784927386 sats; sent=784927386 sats
- `1F8oQoSGLMSouTsu94iXGjBNAt43T97dvY` (p2pkh_compressed): spent_history; derivations=A-07; transactions=4; balance=0 sats; received=11000 sats; sent=11000 sats
- `1KxUVU9DKfdaTLMnXBLS5BZRf56cFnRosk` (p2pkh_uncompressed): spent_history; derivations=A-21,B-049; transactions=6; balance=0 sats; received=516960 sats; sent=516960 sats
- `1MJp4z3ig498hNATfgHBAnLFhwoZpvw118` (p2pkh_compressed): spent_history; derivations=A-16; transactions=6; balance=0 sats; received=451752 sats; sent=451752 sats
- `1Nbm3JoDpwS4HRw9WmHaKGAzaeSKXoQ6Ej` (p2pkh_uncompressed): spent_history; derivations=A-07; transactions=24; balance=0 sats; received=3862600 sats; sent=3862600 sats
- `bc1q34x4pr6m7tpgkg9rsc6qtuza8nfhfvz93895ln` (p2wpkh): spent_history; derivations=A-19,B-029; transactions=6; balance=0 sats; received=11401 sats; sent=11401 sats
- `bc1qmmqwpsupw836pz50c87ze2l4a8xjmvr6x3ww3m` (p2wpkh): spent_history; derivations=A-16; transactions=2; balance=0 sats; received=9779 sats; sent=9779 sats
- `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` (p2wpkh): spent_history; derivations=A-12,B-035; transactions=166; balance=0 sats; received=1447883 sats; sent=1447883 sats

### Interesting observations

- 15 generated address(es) have public chain history.
- 0 are currently funded; 15
  have spent history and zero current balance.
- Public history is a research signal, not a target match. Widely known weak
  keys (for example direct scalar `1`) are expected to have unrelated test or
  sweep activity. The suspected puzzle output remains the separate P2WSH
  program recorded above.

## Hypotheses tested in Stage B

The suspected target is P2WSH (`bc1qfkhx02v89u2qyyyljeczw6hu9sr437y44t7ae5yf09thrdukfqesnjg2wj`). HASH160(pubkey) is the
wrong program length and the wrong script template compared with
`SHA256(witnessScript)`. Stage B therefore does two bounded things:

1. A representation matrix of canonical encodings of primitives physically
   present in the Genesis block (ASCII decimal with newline, hex case and `0x`
   prefixes, fixed-width and distinct minimal endian forms, justified hash
   byte orders, raw header/tx/script/key/block bytes) plus a few exact
   lower-priority semantic UTF-8 strings. Each recipe is SHA256 of a canonical
   encoding, or a direct big-endian integer of a canonical fixed 4-byte or
   8-byte endian byte sequence. No pairwise combinations, dates, typos,
   neighborhoods, PBKDF2/BIP39, or brute force.
2. Six generic single-key witness-script templates, in this global priority,
   compared by exact `SHA256(witnessScript)` and native mainnet P2WSH address
   against witness program `4dae67a9872f1402109f9670276afc2c0758f895aafddcd089795771b7964833`:

    <compressed pubkey> OP_CHECKSIG

Compressed templates are the modern canonical, descriptor-compatible forms.
Uncompressed P2WSH pubkeys were tested only as lower-priority
historical/manual possibilities and are not standard descriptor-compatible.

## Stage B results

Stage B run:
- status: ok
- mode: balanced
- elapsed_seconds: 0.01900291722267866
- rate_per_second: 5525.467420059579
- checkpoint: checkpoint-not-needed

- Stage B derivations: 105
- Stage B invalid derivations: 1
- cumulative unique valid keys after A+B: 105
- cumulative duplicate provenance paths after A+B: 21
- tested witness candidates: 630
- P2WSH direct target matches: 0

Witness templates in actual priority:

- priority 1: `p2pk_compressed` (compressed; modern canonical / descriptor-compatible); tested 105
- priority 2: `p2pk_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 105
- priority 3: `multisig_1of1_compressed` (compressed; modern canonical / descriptor-compatible); tested 105
- priority 4: `multisig_1of1_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 105
- priority 5: `p2pkh_compressed` (compressed; modern canonical / descriptor-compatible); tested 105
- priority 6: `p2pkh_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 105

The 132 Stage-A-only script-template subset is 22 unique Stage A keys times 6 templates. The full combined A+B set is 630 scripts (105 cumulative unique keys times 6 templates). The Stage-A-only subset is contained in the combined set; it is not an extra 132 on top of 630. The executed Stage B run tested 630 witness candidates.

Zero stored witness candidates equal the suspected 32-byte witness program or its native P2WSH address. That does not disprove the puzzle. The announcement target remains `suspected_not_proven`.

All 630 public candidate scripts, programs, addresses, and provenance for the executed Stage B run are stored in SQLite. Scalar material is not stored. This Markdown report does not dump those rows.

## Hypotheses tested in Stage C

Stage C is the implemented bounded pairwise combination of the actual nonce
and timestamp ASCII decimal values (`2083236893` and `1231006505`)
in both orders (`nonce || separator || timestamp` and
`timestamp || separator || nonce`) with exactly these seven separators:

1. empty string `""`
2. colon `":"`
3. pipe `"|"`
4. hyphen `"-"`
5. underscore `"_"`
6. ASCII space `" "`
7. ASCII newline `"\n"`

Each of those 14 public strings is SHA256'd, then the
same six P2WSH templates are applied. No extra fields, dates, neighborhoods,
PBKDF2/BIP39, or brute force.

## Stage C results

Stage C run:
- status: ok
- mode: balanced
- elapsed_seconds: 0.0033158333972096443
- rate_per_second: 4222.1662921247325
- checkpoint: checkpoint-not-needed

- Stage C derivations: 14
- Stage C invalid derivations: 0
- Stage C new unique valid keys: 14
- cumulative unique valid keys after A+B+C: 119
- cumulative duplicate provenance paths after A+B+C: 21
- new Stage C witness candidates: 84
- cumulative B+C witness candidates: 714
- P2WSH direct target matches: 0

Witness templates in actual priority (Stage C keys only; six templates times
14 keys):

- priority 1: `p2pk_compressed` (compressed; modern canonical / descriptor-compatible); tested 14
- priority 2: `p2pk_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 14
- priority 3: `multisig_1of1_compressed` (compressed; modern canonical / descriptor-compatible); tested 14
- priority 4: `multisig_1of1_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 14
- priority 5: `p2pkh_compressed` (compressed; modern canonical / descriptor-compatible); tested 14
- priority 6: `p2pkh_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 14

The 84 new Stage C scripts are 14 unique Stage C keys times 6 templates. The full combined A+B+C set is 714 scripts (119 cumulative unique keys times 6 templates). The executed Stage B run still tested 630 first_tested_stage=B rows; those 630 are preserved and are not replaced. The executed Stage C run tested 84 first_tested_stage=C rows. Combined B+C is 714; it is not an extra 84 on top of 714.

Zero stored Stage C witness candidates equal the suspected 32-byte witness program or its native P2WSH address. That does not disprove the puzzle. The announcement target remains `suspected_not_proven`.

All 84 public Stage C candidate scripts, programs, addresses, and provenance are stored in SQLite alongside the preserved Stage B rows. Scalar material is not stored. This Markdown report does not dump those rows.


## Hypotheses tested in Stage D

Stage D is the implemented bounded direct integer-scalar neighborhood of the
actual Genesis nonce (`2083236893`) and timestamp (`1231006505`).
Canonical direct nonce and timestamp values were already Stage A, so offset
zero is excluded. Offsets are ±1..±10. Priority is distance-first: for each
distance d from 1 to 10, nonce-d, nonce+d, timestamp-d, timestamp+d. No hashing.

Each of those 40 recipes is the identity integer
`k = uint(field=public_value) + (signed_offset)`. public_input bytes stay
empty. The raw scalar is not stored or logged. The formula, signed offset,
and fingerprint are sufficient to recompute the same public key.

Exact order:

1. `k = uint(nonce=2083236893) + (-1)`
2. `k = uint(nonce=2083236893) + (+1)`
3. `k = uint(timestamp=1231006505) + (-1)`
4. `k = uint(timestamp=1231006505) + (+1)`
5. `k = uint(nonce=2083236893) + (-2)`
6. `k = uint(nonce=2083236893) + (+2)`
7. `k = uint(timestamp=1231006505) + (-2)`
8. `k = uint(timestamp=1231006505) + (+2)`
9. `k = uint(nonce=2083236893) + (-3)`
10. `k = uint(nonce=2083236893) + (+3)`
11. `k = uint(timestamp=1231006505) + (-3)`
12. `k = uint(timestamp=1231006505) + (+3)`
13. `k = uint(nonce=2083236893) + (-4)`
14. `k = uint(nonce=2083236893) + (+4)`
15. `k = uint(timestamp=1231006505) + (-4)`
16. `k = uint(timestamp=1231006505) + (+4)`
17. `k = uint(nonce=2083236893) + (-5)`
18. `k = uint(nonce=2083236893) + (+5)`
19. `k = uint(timestamp=1231006505) + (-5)`
20. `k = uint(timestamp=1231006505) + (+5)`
21. `k = uint(nonce=2083236893) + (-6)`
22. `k = uint(nonce=2083236893) + (+6)`
23. `k = uint(timestamp=1231006505) + (-6)`
24. `k = uint(timestamp=1231006505) + (+6)`
25. `k = uint(nonce=2083236893) + (-7)`
26. `k = uint(nonce=2083236893) + (+7)`
27. `k = uint(timestamp=1231006505) + (-7)`
28. `k = uint(timestamp=1231006505) + (+7)`
29. `k = uint(nonce=2083236893) + (-8)`
30. `k = uint(nonce=2083236893) + (+8)`
31. `k = uint(timestamp=1231006505) + (-8)`
32. `k = uint(timestamp=1231006505) + (+8)`
33. `k = uint(nonce=2083236893) + (-9)`
34. `k = uint(nonce=2083236893) + (+9)`
35. `k = uint(timestamp=1231006505) + (-9)`
36. `k = uint(timestamp=1231006505) + (+9)`
37. `k = uint(nonce=2083236893) + (-10)`
38. `k = uint(nonce=2083236893) + (+10)`
39. `k = uint(timestamp=1231006505) + (-10)`
40. `k = uint(timestamp=1231006505) + (+10)`

The same six P2WSH templates are applied. No extra fields, dates, combinations,
PBKDF2/BIP39, or brute force.

## Stage D results

Stage D run:
- status: ok
- mode: balanced
- elapsed_seconds: 0.008176499977707863
- rate_per_second: 4892.06874690328
- checkpoint: checkpoint-not-needed

- Stage D derivations: 40
- Stage D invalid derivations: 0
- Stage D new unique valid keys: 40
- cumulative unique valid keys after A+B+C+D: 159
- cumulative duplicate provenance paths after A+B+C+D: 21
- new Stage D witness candidates: 240
- cumulative B+C+D witness candidates: 954
- P2WSH direct target matches: 0

Witness templates in actual priority (Stage D keys only; six templates times
40 keys):

- priority 1: `p2pk_compressed` (compressed; modern canonical / descriptor-compatible); tested 40
- priority 2: `p2pk_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 40
- priority 3: `multisig_1of1_compressed` (compressed; modern canonical / descriptor-compatible); tested 40
- priority 4: `multisig_1of1_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 40
- priority 5: `p2pkh_compressed` (compressed; modern canonical / descriptor-compatible); tested 40
- priority 6: `p2pkh_uncompressed` (uncompressed; lower-priority historical/manual possibility, not standard descriptor-compatible); tested 40

The 240 new Stage D scripts are 40 unique Stage D keys times 6 templates. The full combined A+B+C+D set is 954 scripts (159 cumulative unique keys times 6 templates). The executed Stage B run still tested 630 first_tested_stage=B rows; those 630 are preserved and are not replaced. The executed Stage C run still tested 84 first_tested_stage=C rows; those 84 are preserved and are not replaced. The executed Stage D run tested 240 first_tested_stage=D rows. Combined B+C remains 714. Combined B+C+D is 954; it is not an extra 240 on top of 954.

Zero stored Stage D witness candidates equal the suspected 32-byte witness program or its native P2WSH address. That does not disprove the puzzle. The announcement target remains `suspected_not_proven`.

All 240 public Stage D candidate scripts, programs, addresses, and provenance are stored in SQLite alongside the preserved Stage B and Stage C rows. Scalar material is not stored. public_input bytes stay empty. The raw scalar is not stored or logged. Formula, signed offset, and fingerprint are sufficient to recompute. This Markdown report does not dump those rows.


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
- `B-001` [valid] SHA256 of the ASCII decimal nonce followed by a newline. (source `genesis.header.nonce`, transform `sha256`, confidence 0.34)
- `B-002` [valid] SHA256 of the lowercase hex nonce without prefix. (source `genesis.header.nonce`, transform `sha256`, confidence 0.34)
- `B-003` [valid] SHA256 of the uppercase hex nonce without prefix. (source `genesis.header.nonce`, transform `sha256`, confidence 0.34)
- `B-004` [valid] SHA256 of the 0x-prefixed lowercase hex nonce. (source `genesis.header.nonce`, transform `sha256`, confidence 0.34)
- `B-005` [valid] SHA256 of the 0X-prefixed uppercase hex nonce. (source `genesis.header.nonce`, transform `sha256`, confidence 0.34)
- `B-006` [valid] SHA256 of the 4-byte little-endian nonce. (source `genesis.header.nonce`, transform `sha256`, confidence 0.34)
- `B-007` [valid] Direct big-endian integer of the 4-byte little-endian nonce. (source `genesis.header.nonce`, transform `identity_bytes_be`, confidence 0.34)
- `B-008` [valid] SHA256 of the 4-byte big-endian nonce. (source `genesis.header.nonce`, transform `sha256`, confidence 0.34)
- `B-009` [valid] Direct big-endian integer of the 4-byte big-endian nonce. (source `genesis.header.nonce`, transform `identity_bytes_be`, confidence 0.34)
- `B-010` [valid] SHA256 of the ASCII decimal timestamp followed by a newline. (source `genesis.header.timestamp`, transform `sha256`, confidence 0.33)
- `B-011` [valid] SHA256 of the lowercase hex timestamp without prefix. (source `genesis.header.timestamp`, transform `sha256`, confidence 0.33)
- `B-012` [valid] SHA256 of the uppercase hex timestamp without prefix. (source `genesis.header.timestamp`, transform `sha256`, confidence 0.33)
- `B-013` [valid] SHA256 of the 0x-prefixed lowercase hex timestamp. (source `genesis.header.timestamp`, transform `sha256`, confidence 0.33)
- `B-014` [valid] SHA256 of the 0X-prefixed uppercase hex timestamp. (source `genesis.header.timestamp`, transform `sha256`, confidence 0.33)
- `B-015` [valid] SHA256 of the 4-byte little-endian timestamp. (source `genesis.header.timestamp`, transform `sha256`, confidence 0.33)
- `B-016` [valid] Direct big-endian integer of the 4-byte little-endian timestamp. (source `genesis.header.timestamp`, transform `identity_bytes_be`, confidence 0.33)
- `B-017` [valid] SHA256 of the 4-byte big-endian timestamp. (source `genesis.header.timestamp`, transform `sha256`, confidence 0.33)
- `B-018` [valid] Direct big-endian integer of the 4-byte big-endian timestamp. (source `genesis.header.timestamp`, transform `identity_bytes_be`, confidence 0.33)
- `B-019` [valid] SHA256 of the ASCII decimal bits followed by a newline. (source `genesis.header.bits`, transform `sha256`, confidence 0.32)
- `B-020` [valid] SHA256 of the lowercase hex bits without prefix. (source `genesis.header.bits`, transform `sha256`, confidence 0.32)
- `B-021` [valid] SHA256 of the uppercase hex bits without prefix. (source `genesis.header.bits`, transform `sha256`, confidence 0.32)
- `B-022` [valid] SHA256 of the 0x-prefixed lowercase hex bits. (source `genesis.header.bits`, transform `sha256`, confidence 0.32)
- `B-023` [valid] SHA256 of the 0X-prefixed uppercase hex bits. (source `genesis.header.bits`, transform `sha256`, confidence 0.32)
- `B-024` [valid] SHA256 of the 4-byte little-endian bits. (source `genesis.header.bits`, transform `sha256`, confidence 0.32)
- `B-025` [valid] Direct big-endian integer of the 4-byte little-endian bits. (source `genesis.header.bits`, transform `identity_bytes_be`, confidence 0.32)
- `B-026` [valid] SHA256 of the 4-byte big-endian bits. (source `genesis.header.bits`, transform `sha256`, confidence 0.32)
- `B-027` [valid] Direct big-endian integer of the 4-byte big-endian bits. (source `genesis.header.bits`, transform `identity_bytes_be`, confidence 0.32)
- `B-028` [valid] SHA256 of the ASCII decimal version followed by a newline. (source `genesis.header.version`, transform `sha256`, confidence 0.31)
- `B-029` [valid] SHA256 of the lowercase hex version without prefix. (source `genesis.header.version`, transform `sha256`, confidence 0.31)
- `B-030` [valid] SHA256 of the 0x-prefixed lowercase hex version. (source `genesis.header.version`, transform `sha256`, confidence 0.31)
- `B-031` [valid] SHA256 of the 0X-prefixed uppercase hex version. (source `genesis.header.version`, transform `sha256`, confidence 0.31)
- `B-032` [valid] SHA256 of the 4-byte little-endian version. (source `genesis.header.version`, transform `sha256`, confidence 0.31)
- `B-033` [valid] Direct big-endian integer of the 4-byte little-endian version. (source `genesis.header.version`, transform `identity_bytes_be`, confidence 0.31)
- `B-034` [valid] SHA256 of the 4-byte big-endian version. (source `genesis.header.version`, transform `sha256`, confidence 0.31)
- `B-035` [valid] Direct big-endian integer of the 4-byte big-endian version. (source `genesis.header.version`, transform `identity_bytes_be`, confidence 0.31)
- `B-036` [valid] SHA256 of the minimal unsigned big-endian version. (source `genesis.header.version`, transform `sha256`, confidence 0.31)
- `B-037` [valid] SHA256 of the ASCII decimal reward_sats followed by a newline. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-038` [valid] SHA256 of the lowercase hex reward_sats without prefix. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-039` [valid] SHA256 of the uppercase hex reward_sats without prefix. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-040` [valid] SHA256 of the 0x-prefixed lowercase hex reward_sats. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-041` [valid] SHA256 of the 0X-prefixed uppercase hex reward_sats. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-042` [valid] SHA256 of the 8-byte little-endian reward_sats. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-043` [valid] Direct big-endian integer of the 8-byte little-endian reward_sats. (source `genesis.tx.reward_sats`, transform `identity_bytes_be`, confidence 0.3)
- `B-044` [valid] SHA256 of the 8-byte big-endian reward_sats. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-045` [valid] Direct big-endian integer of the 8-byte big-endian reward_sats. (source `genesis.tx.reward_sats`, transform `identity_bytes_be`, confidence 0.3)
- `B-046` [valid] SHA256 of the minimal unsigned big-endian reward_sats. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-047` [valid] SHA256 of the minimal unsigned little-endian reward_sats. (source `genesis.tx.reward_sats`, transform `sha256`, confidence 0.3)
- `B-048` [valid] SHA256 of the ASCII decimal height followed by a newline. (source `genesis.height`, transform `sha256`, confidence 0.22)
- `B-049` [valid] SHA256 of the lowercase hex height without prefix. (source `genesis.height`, transform `sha256`, confidence 0.22)
- `B-050` [valid] SHA256 of the 0x-prefixed lowercase hex height. (source `genesis.height`, transform `sha256`, confidence 0.22)
- `B-051` [valid] SHA256 of the 0X-prefixed uppercase hex height. (source `genesis.height`, transform `sha256`, confidence 0.22)
- `B-052` [valid] SHA256 of the 4-byte little-endian height. (source `genesis.height`, transform `sha256`, confidence 0.22)
- `B-053` [eliminated] Direct big-endian integer of the 4-byte little-endian height. (source `genesis.height`, transform `identity_bytes_be`, confidence 0.22)
- `B-054` [valid] SHA256 of the minimal unsigned big-endian height. (source `genesis.height`, transform `sha256`, confidence 0.22)
- `B-055` [valid] SHA256 of the block hash raw/wire bytes. (source `genesis.block_hash`, transform `sha256`, confidence 0.21)
- `B-056` [valid] SHA256 of the block hash display-order bytes. (source `genesis.block_hash`, transform `sha256`, confidence 0.21)
- `B-057` [valid] SHA256 of the lowercase ASCII hex block hash in wire order. (source `genesis.block_hash`, transform `sha256`, confidence 0.21)
- `B-058` [valid] SHA256 of the uppercase ASCII hex block hash in wire order. (source `genesis.block_hash`, transform `sha256`, confidence 0.21)
- `B-059` [valid] SHA256 of the lowercase ASCII hex block hash in display order. (source `genesis.block_hash`, transform `sha256`, confidence 0.21)
- `B-060` [valid] SHA256 of the uppercase ASCII hex block hash in display order. (source `genesis.block_hash`, transform `sha256`, confidence 0.21)
- `B-061` [valid] SHA256 of the lowercase display ASCII hex block hash followed by a newline. (source `genesis.block_hash`, transform `sha256`, confidence 0.21)
- `B-062` [valid] SHA256 of the Merkle root raw/wire bytes. (source `genesis.merkle_root`, transform `sha256`, confidence 0.2)
- `B-063` [valid] SHA256 of the Merkle root display-order bytes. (source `genesis.merkle_root`, transform `sha256`, confidence 0.2)
- `B-064` [valid] SHA256 of the lowercase ASCII hex Merkle root in wire order. (source `genesis.merkle_root`, transform `sha256`, confidence 0.2)
- `B-065` [valid] SHA256 of the uppercase ASCII hex Merkle root in wire order. (source `genesis.merkle_root`, transform `sha256`, confidence 0.2)
- `B-066` [valid] SHA256 of the lowercase ASCII hex Merkle root in display order. (source `genesis.merkle_root`, transform `sha256`, confidence 0.2)
- `B-067` [valid] SHA256 of the uppercase ASCII hex Merkle root in display order. (source `genesis.merkle_root`, transform `sha256`, confidence 0.2)
- `B-068` [valid] SHA256 of the lowercase display ASCII hex Merkle root followed by a newline. (source `genesis.merkle_root`, transform `sha256`, confidence 0.2)
- `B-069` [valid] SHA256 of the coinbase txid raw/wire bytes. (source `genesis.txid`, transform `sha256`, confidence 0.19)
- `B-070` [valid] SHA256 of the coinbase txid display-order bytes. (source `genesis.txid`, transform `sha256`, confidence 0.19)
- `B-071` [valid] SHA256 of the lowercase ASCII hex coinbase txid in wire order. (source `genesis.txid`, transform `sha256`, confidence 0.19)
- `B-072` [valid] SHA256 of the uppercase ASCII hex coinbase txid in wire order. (source `genesis.txid`, transform `sha256`, confidence 0.19)
- `B-073` [valid] SHA256 of the lowercase ASCII hex coinbase txid in display order. (source `genesis.txid`, transform `sha256`, confidence 0.19)
- `B-074` [valid] SHA256 of the uppercase ASCII hex coinbase txid in display order. (source `genesis.txid`, transform `sha256`, confidence 0.19)
- `B-075` [valid] SHA256 of the lowercase display ASCII hex coinbase txid followed by a newline. (source `genesis.txid`, transform `sha256`, confidence 0.19)
- `B-076` [valid] SHA256 of the previous block hash. (source `genesis.header.previous_hash`, transform `sha256`, confidence 0.17)
- `B-077` [valid] SHA256 of the lowercase ASCII hex previous block hash. (source `genesis.header.previous_hash`, transform `sha256`, confidence 0.17)
- `B-078` [valid] SHA256 of the expanded target. (source `genesis.header.target`, transform `sha256`, confidence 0.16)
- `B-079` [valid] SHA256 of the lowercase ASCII hex expanded target. (source `genesis.header.target`, transform `sha256`, confidence 0.16)
- `B-080` [valid] SHA256 of the uppercase ASCII hex expanded target. (source `genesis.header.target`, transform `sha256`, confidence 0.16)
- `B-081` [valid] SHA256 of the raw 80-byte header. (source `genesis.header.raw`, transform `sha256`, confidence 0.14)
- `B-082` [valid] SHA256 of the lowercase ASCII hex raw 80-byte header. (source `genesis.header.raw`, transform `sha256`, confidence 0.14)
- `B-083` [valid] SHA256 of the uppercase ASCII hex raw 80-byte header. (source `genesis.header.raw`, transform `sha256`, confidence 0.14)
- `B-084` [valid] SHA256 of the raw coinbase transaction. (source `genesis.tx.raw`, transform `sha256`, confidence 0.13)
- `B-085` [valid] SHA256 of the lowercase ASCII hex raw coinbase transaction. (source `genesis.tx.raw`, transform `sha256`, confidence 0.13)
- `B-086` [valid] SHA256 of the uppercase ASCII hex raw coinbase transaction. (source `genesis.tx.raw`, transform `sha256`, confidence 0.13)
- `B-087` [valid] SHA256 of the coinbase scriptSig. (source `genesis.coinbase.script_sig`, transform `sha256`, confidence 0.12)
- `B-088` [valid] SHA256 of the lowercase ASCII hex coinbase scriptSig. (source `genesis.coinbase.script_sig`, transform `sha256`, confidence 0.12)
- `B-089` [valid] SHA256 of the uppercase ASCII hex coinbase scriptSig. (source `genesis.coinbase.script_sig`, transform `sha256`, confidence 0.12)
- `B-090` [valid] SHA256 of the coinbase scriptPubKey. (source `genesis.coinbase.script_pubkey`, transform `sha256`, confidence 0.11)
- `B-091` [valid] SHA256 of the lowercase ASCII hex coinbase scriptPubKey. (source `genesis.coinbase.script_pubkey`, transform `sha256`, confidence 0.11)
- `B-092` [valid] SHA256 of the uppercase ASCII hex coinbase scriptPubKey. (source `genesis.coinbase.script_pubkey`, transform `sha256`, confidence 0.11)
- `B-093` [valid] SHA256 of the Genesis public key. (source `genesis.coinbase.pubkey`, transform `sha256`, confidence 0.1)
- `B-094` [valid] SHA256 of the lowercase ASCII hex Genesis public key. (source `genesis.coinbase.pubkey`, transform `sha256`, confidence 0.1)
- `B-095` [valid] SHA256 of the uppercase ASCII hex Genesis public key. (source `genesis.coinbase.pubkey`, transform `sha256`, confidence 0.1)
- `B-096` [valid] SHA256 of the complete raw Genesis block. (source `genesis.block.raw`, transform `sha256`, confidence 0.09)
- `B-097` [valid] SHA256 of the lowercase ASCII hex complete raw Genesis block. (source `genesis.block.raw`, transform `sha256`, confidence 0.09)
- `B-098` [valid] SHA256 of the uppercase ASCII hex complete raw Genesis block. (source `genesis.block.raw`, transform `sha256`, confidence 0.09)
- `B-099` [valid] SHA256 of the exact coinbase headline UTF-8 bytes followed by a newline. (source `genesis.coinbase.headline`, transform `sha256`, confidence 0.08)
- `B-100` [valid] SHA256 of the lowercase coinbase headline UTF-8 bytes. (source `genesis.coinbase.headline`, transform `sha256`, confidence 0.08)
- `B-101` [valid] SHA256 of the uppercase coinbase headline UTF-8 bytes. (source `genesis.coinbase.headline`, transform `sha256`, confidence 0.08)
- `B-102` [valid] SHA256 of the exact UTF-8 string 'Satoshi Nakamoto'. (source `text.satoshi_nakamoto`, transform `sha256`, confidence 0.04)
- `B-103` [valid] SHA256 of the exact UTF-8 string 'Bitcoin'. (source `text.bitcoin`, transform `sha256`, confidence 0.04)
- `B-104` [valid] SHA256 of the exact UTF-8 string 'genesis'. (source `text.genesis`, transform `sha256`, confidence 0.04)
- `B-105` [valid] SHA256 of the exact UTF-8 string 'genesis block'. (source `text.genesis_block`, transform `sha256`, confidence 0.04)
- `C-001` [valid] SHA256 of the ASCII decimal nonce followed by empty string "" followed by the ASCII decimal timestamp. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.18)
- `C-002` [valid] SHA256 of the ASCII decimal timestamp followed by empty string "" followed by the ASCII decimal nonce. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.175)
- `C-003` [valid] SHA256 of the ASCII decimal nonce followed by colon ":" followed by the ASCII decimal timestamp. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.17)
- `C-004` [valid] SHA256 of the ASCII decimal timestamp followed by colon ":" followed by the ASCII decimal nonce. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.165)
- `C-005` [valid] SHA256 of the ASCII decimal nonce followed by pipe "|" followed by the ASCII decimal timestamp. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.16)
- `C-006` [valid] SHA256 of the ASCII decimal timestamp followed by pipe "|" followed by the ASCII decimal nonce. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.155)
- `C-007` [valid] SHA256 of the ASCII decimal nonce followed by hyphen "-" followed by the ASCII decimal timestamp. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.15)
- `C-008` [valid] SHA256 of the ASCII decimal timestamp followed by hyphen "-" followed by the ASCII decimal nonce. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.145)
- `C-009` [valid] SHA256 of the ASCII decimal nonce followed by underscore "_" followed by the ASCII decimal timestamp. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.14)
- `C-010` [valid] SHA256 of the ASCII decimal timestamp followed by underscore "_" followed by the ASCII decimal nonce. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.135)
- `C-011` [valid] SHA256 of the ASCII decimal nonce followed by ASCII space " " followed by the ASCII decimal timestamp. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.13)
- `C-012` [valid] SHA256 of the ASCII decimal timestamp followed by ASCII space " " followed by the ASCII decimal nonce. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.125)
- `C-013` [valid] SHA256 of the ASCII decimal nonce followed by ASCII newline "\n" followed by the ASCII decimal timestamp. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.12)
- `C-014` [valid] SHA256 of the ASCII decimal timestamp followed by ASCII newline "\n" followed by the ASCII decimal nonce. (source `genesis.header.nonce_and_timestamp`, transform `sha256`, confidence 0.115)
- `D-001` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -1 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.25)
- `D-002` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +1 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.248)
- `D-003` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -1 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.246)
- `D-004` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +1 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.244)
- `D-005` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -2 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.242)
- `D-006` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +2 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.24)
- `D-007` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -2 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.238)
- `D-008` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +2 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.236)
- `D-009` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -3 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.234)
- `D-010` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +3 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.232)
- `D-011` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -3 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.23)
- `D-012` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +3 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.228)
- `D-013` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -4 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.226)
- `D-014` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +4 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.224)
- `D-015` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -4 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.222)
- `D-016` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +4 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.22)
- `D-017` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -5 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.218)
- `D-018` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +5 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.216)
- `D-019` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -5 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.214)
- `D-020` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +5 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.212)
- `D-021` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -6 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.21)
- `D-022` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +6 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.208)
- `D-023` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -6 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.206)
- `D-024` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +6 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.204)
- `D-025` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -7 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.202)
- `D-026` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +7 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.2)
- `D-027` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -7 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.198)
- `D-028` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +7 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.196)
- `D-029` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -8 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.194)
- `D-030` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +8 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.192)
- `D-031` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -8 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.19)
- `D-032` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +8 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.188)
- `D-033` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -9 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.186)
- `D-034` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +9 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.184)
- `D-035` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -9 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.182)
- `D-036` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +9 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.18)
- `D-037` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset -10 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.178)
- `D-038` [valid] Interpret the public Genesis header nonce 2083236893 plus signed offset +10 as a secp256k1 scalar. (source `genesis.header.nonce`, transform `identity_integer`, confidence 0.176)
- `D-039` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset -10 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.174)
- `D-040` [valid] Interpret the public Genesis header timestamp 1231006505 plus signed offset +10 as a secp256k1 scalar. (source `genesis.header.timestamp`, transform `identity_integer`, confidence 0.172)

### Eliminated hypotheses

- `A-14`: height_zero_invalid_direct_scalar
- `B-053`: scalar_out_of_range

### Remaining hypotheses

180 stored valid derivation ids remain open as public-key hypotheses, not as matches. They are listed once under Derivations. Stage A P2PKH/P2WPKH addresses still do not test the P2WSH program. The six generic single-key P2WSH templates did not match the target on the preserved Stage B set, the 14 new Stage C keys, or the 40 new Stage D keys. Other scripts and encodings remain untested.

A miss of these six templates on the executed Stage D keys is not a proof that no puzzle exists. Remaining open work is other scripts, other encodings, and the bounded Stage E experiment below.

## Next highest-value Stage E experiment (not executed)

Hypothesis, not a claim: after the executed Stage A+B+C+D set, the single
highest-value next experiment is SHA256 once over exactly these eight UTF-8
date/time strings, in this order:

1. `2009-01-03T18:15:05Z`
2. `2009-01-03 18:15:05 UTC`
3. `2009-01-03`
4. `03/Jan/2009`
5. `03/01/2009` (European/day-first ambiguous)
6. `01/03/2009` (American/month-first ambiguous)
7. `03Jan2009`
8. `20090103`

Eight candidate keys, at most 48 scripts. Do not add
newline, case, or whitespace variants. Do not add alternate time zones or
other dates. Do not use PBKDF2, BIP39, repeated hashing, GPU, neighborhoods,
larger combinations, or brute force. Do not execute Stage E here.

## Resource and safety notes

- Balanced mode is the default. Stage A, Stage B, Stage C, and Stage D are sequential.
- Pause/resume/checkpointing are future bounded-search features and are not
  needed here (`checkpoint-not-needed`).
- GPU is disabled. No temperature is measured.
- Offline is the default. Stage B, Stage C, and Stage D never query chain history. Remote history checks are explicit, batched, and send derived public addresses only.
- Do not paste candidate scalars into a wallet. This tool will not import
  keys, build transactions, or broadcast.

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
