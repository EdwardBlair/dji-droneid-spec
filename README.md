# DJI O4 DroneID CRYP and INFP Specification

[中文](README_CN.md)

RF waveform, channel sequence, and passive demodulation: [`RF_PHY.md`](RF_PHY.md)

## Scope

This document specifies the DJI O4 DroneID `CRYP`, `INFP-10`, and
`INFP-11` formats. It covers packet envelopes, core records, cryptographic
processing, session association, decrypted payload layouts, and validation.

`CRYP` establishes a 128-bit AES session key using SM2 public-key encryption.
The session key decrypts both the auxiliary payload carried by that `CRYP`
record and the associated `INFP` records. A four-byte key identifier associates
records with the correct session.

The specification is based on packet analysis and the reference implementation
in this repository.

## Validation with a known session key

The reference implementation accepts an already-unwrapped 16-byte AES session
key as an external input. It checks `key_id = SHA-256(K)[0:4]`, decrypts
the CRYP auxiliary and associated INFP ciphertexts, and validates their
plaintext schemas. This mode neither discovers nor unwraps `K`.

An externally supplied `K` is not sufficient to authenticate the captured
CRYP `C3`, because that calculation also uses the SM2 shared point `(x2, y2)`.
The implementation reports that check as `notChecked`. INFP payload decryption
and schema validation use `K` directly.

No recipient private key is needed to construct a CRYP packet: the sender uses
`Q`, while `d` is needed only by the recipient to unwrap and authenticate the
transported session key.

Compatible recipient public material is not included. It can be extracted from
firmware from a supported device and supplied with `--public-key-file`. See
`EXAMPLE.md` for the file format, command-line usage, and round-trip example.

## Recipient private-key custody

The SM2 recipient private key corresponding to `Q` is held by the DJI
AeroScope Upgrade Module, model EA500. It is a hardware-backed USB
cryptographic module supplied in fixed-site and mobile form factors. The two
forms differ physically but perform the same cryptographic function.

The AeroScope host and upgrade module perform a multi-step authentication
exchange and establish a separate encrypted transport session. The host sends
the CRYP record to the module unchanged. The module unwraps and returns the
16-byte session key `K`; the long-term recipient private key `d` remains inside
the module.

The host-to-module command protocol has been recovered but is not published.

## Conventions

- Offsets are zero-based and measured in bytes.
- Multi-byte integers are little-endian unless a field explicitly says
  otherwise.
- Elliptic-curve coordinates and scalars are unsigned big-endian integers.
- `||` means byte-string concatenation.
- `XOR` means bytewise exclusive OR over equal-length strings.
- `0x00 × n` means `n` zero bytes.
- Text is UTF-8 unless a field has a stricter character set.
- `K` is the 16-byte AES session key.
- `d` is the recipient's SM2 private scalar.
- `Q = dG` is the recipient's SM2 public point.
- `k` is the sender's fresh SM2 ephemeral scalar.
- `C1`, `C2`, and `C3` are the three components of the SM2-encrypted session
  key.

## Protocol overview

The transmitter creates a `CRYP` record for a session and sends one or more
`INFP` records carrying data from that session. All records in the session carry
the same four-byte `key_id`.

The high-level transmitter flow is:

1. Generate a 16-byte AES session key `K`.
2. Encrypt `K` for the recipient using SM2, producing `C1`, `C2`, and `C3`.
3. Set `key_id = SHA-256(K)[0:4]`.
4. Encrypt the 32-byte CRYP auxiliary plaintext with AES-128-CTR under `K`.
5. Encrypt each INFP plaintext with AES-128-CTR under `K` and a per-record IV.

The receiver flow is:

1. Parse and validate a `CRYP` core record.
2. Use private scalar `d` to recover and authenticate `K` from `C1`, `C2`, and
   `C3`.
3. Confirm that `SHA-256(K)[0:4]` equals the record's `key_id`.
4. Associate `K` with `key_id`.
5. Decrypt the CRYP auxiliary ciphertext and every INFP record carrying the
   same `key_id`.

Record arrival order is unrestricted. INFP records can be buffered until their
CRYP record arrives or processed in a later pass.

## Packet envelopes

The CRYP and INFP core records can appear directly or inside either of two
envelopes. Envelope handling produces one core record for the parser.

### Direct core record

A direct record begins with one of the following selectors and has the stated
exact length:

| Selector | Magic at offsets 1–4 | Core type | Length |
| ---: | --- | --- | ---: |
| `0x10` | `INFP` | INFP-10 | 128 |
| `0x11` | `INFP` | INFP-11 | 160 |
| `0x13` | `CRYP` | CRYP | 163 |

### Logical-object envelope

The logical-object envelope has this layout:

| Offset | Size | Field | Encoding |
| ---: | ---: | --- | --- |
| 0 | 1 | `payload_length` | Unsigned byte |
| 1 | `payload_length` | Payload | Core record followed by optional transport padding |
| `1 + payload_length` | 2 | `crc16` | Little-endian |

The total envelope length is `payload_length + 3`. The payload begins with one
complete CRYP or INFP core. Some records append seven zero bytes after
the core. A parser uses the selector-defined core length and treats any
remaining payload bytes as transport padding. The CRC covers the length byte
and complete payload, but not the two-byte stored CRC.

### V1 transport envelope

The V1 transport envelope has this layout:

| Offset | Size | Field | Encoding or requirement |
| ---: | ---: | --- | --- |
| 0 | 1 | Start marker | Must be `0x55` |
| 1 | 1 | Declared length low byte | Unsigned |
| 2 | 1 | Length and transport flags | Bits 0–1 are declared-length bits 8–9 |
| 3 | 1 | Header CRC | CRC-8 over offsets 0–2 |
| 4 | 5 | Transport metadata | Preserved by the transport layer |
| 9 | 2 | Service identifier | Must be `03 da` |
| 11 | variable | Service payload | Core record followed by any transport extension |
| final 2 | 2 | Frame CRC | CRC-16, little-endian |

The declared total length is:

```text
declared_length = byte[1] | ((byte[2] & 0x03) << 8)
```

It must equal the complete frame length. The frame CRC covers every byte except
the final two-byte stored CRC.

### CRC algorithms

CRC-8 uses an initial value of `0x77`, reflected polynomial `0x8c`, and no final
XOR:

```text
crc = 0x77
for byte in input:
    crc = crc XOR byte
    repeat 8 times:
        crc = (crc >> 1) XOR 0x8c  if (crc & 1) != 0
              crc >> 1             otherwise
return crc & 0xff
```

CRC-16 uses an initial value of `0x3692`, reflected polynomial `0x8408`, and no
final XOR. The stored result is little-endian:

```text
crc = 0x3692
for byte in input:
    crc = crc XOR byte
    repeat 8 times:
        crc = (crc >> 1) XOR 0x8408  if (crc & 1) != 0
              crc >> 1               otherwise
return crc & 0xffff
```

## Cryptographic parameters

### SM2 curve

The protocol uses the standard 256-bit SM2 curve over the prime field `Fp`:

```text
p  = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n  = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
```

The recipient public point `Q` is public material that can be extracted from
firmware from a supported device. It is not included here.

Points use affine coordinates. The wire encoding of `C1` is the 32-byte
big-endian X coordinate followed by the 32-byte big-endian Y coordinate. There
is no SEC1 `0x04` uncompressed-point prefix.

### SM2 session-key encryption

To transport session key `K`, the sender performs:

```text
choose fresh k such that 1 <= k < n
C1 = kG
S  = kQ = (x2, y2)
t  = SM3(x2 || y2 || 00000001)[0:16]
C2 = K XOR t
C3 = SM3(x2 || K || y2)
key_id = SHA-256(K)[0:4]
```

`x2` and `y2` are each encoded as exactly 32 big-endian bytes. `00000001` is
the four-byte big-endian KDF counter value one. The resulting `t` is the first
16 bytes of the 32-byte SM3 digest. If `t` is all zero, the sender must restart
the SM2 encryption operation with a new `k`.

The receiver performs:

```text
decode C1 as point (x1, y1)
validate C1
S  = dC1 = (x2, y2)
t  = SM3(x2 || y2 || 00000001)[0:16]
K  = C2 XOR t
require SM3(x2 || K || y2) == C3
require SHA-256(K)[0:4] == key_id
```

The receiver must reject `C1` unless both coordinates are in `[0, p - 1]`, the
point satisfies the SM2 curve equation, and multiplication by `d` does not
produce the point at infinity. Compare digests in constant time.

### AES-CTR payload encryption

CRYP auxiliary data and INFP plaintexts use AES-128 in CTR mode. Each core
record supplies an eight-byte `iv`. Construct the 16-byte initial counter as:

```text
initial_counter = iv || (0x00 × 8)
```

Encryption and decryption are the same CTR transformation. There is no padding.
The initial counter is interpreted as a 128-bit big-endian integer and is
incremented by one for each subsequent block.

AES-CTR does not authenticate ciphertext. `C3` authenticates the transported
session key, not the CRYP auxiliary ciphertext or INFP ciphertext. Envelope
CRCs detect transmission errors but do not provide cryptographic
authentication. Record authentication requires a separate mechanism.

## Session association

Every CRYP and INFP core contains a four-byte `key_id`. Its value is:

```text
key_id = SHA-256(K)[0:4]
```

A receiver must not accept a CRYP-derived key until this value and `C3` both
validate. An INFP record is decrypted only with the authenticated session key
associated with its exact four-byte `key_id`.

The identifier is a truncated key digest and is not a substitute for the `C3`
integrity check. Identifier collisions are possible; do not assume global
uniqueness.

## CRYP core record

The CRYP core is exactly 163 bytes:

| Offset | Size | Field | Encoding or value |
| ---: | ---: | --- | --- |
| 0 | 1 | Selector | `0x13` |
| 1 | 4 | Magic | ASCII `CRYP` |
| 5 | 4 | `key_id` | First four bytes of `SHA-256(K)` |
| 9 | 32 | `C1.x` | Unsigned big-endian |
| 41 | 32 | `C1.y` | Unsigned big-endian |
| 73 | 32 | `C3` | SM3 authentication digest |
| 105 | 16 | `C2` | Masked AES session key |
| 121 | 8 | `iv` | AES-CTR IV prefix |
| 129 | 2 | Ciphertext length | Little-endian `0x0020` |
| 131 | 32 | Auxiliary ciphertext | AES-128-CTR encrypted |

The wire ordering is `C1 || C3 || C2`, not the `C1 || C2 || C3` ordering often
used when writing SM2 ciphertexts.

### CRYP auxiliary plaintext

Decrypt offsets 131–162 with `K` and the CRYP IV. The resulting plaintext is
exactly 32 bytes:

| Offset | Size | Field | Encoding and scale |
| ---: | ---: | --- | --- |
| 0 | 16 | Aircraft identifier | NUL-terminated or NUL-padded ASCII |
| 16 | 4 | Aircraft longitude | Signed little-endian radians × 10,000,000 |
| 20 | 4 | Aircraft latitude | Signed little-endian radians × 10,000,000 |
| 24 | 1 | Position-validity flags | Bit field |
| 25 | 7 | Reserved | Preserve as opaque bytes |

Coordinate conversion is:

```text
degrees = raw / 10,000,000 × 180 / pi
```

The position-validity flags are:

| Bit | Name | Meaning |
| ---: | --- | --- |
| 0 | `aircraftPositionValid` | Longitude and latitude are valid when set |
| 1 | `positionProducerMarker` | Observed producer marker |
| 2–7 | Reserved | Meaning unassigned; preserve |

When bit 0 is set, longitude must be in `[-180, 180]` degrees and latitude must
be in `[-90, 90]` degrees. When bit 0 is clear, both coordinates are
unavailable regardless of their stored numeric values.

The aircraft identifier is the byte sequence before the first NUL. Accept only
a non-empty ASCII alphanumeric identifier (`0`–`9`, `A`–`Z`, or `a`–`z`). An
invalid identifier can be reported as unavailable without invalidating the
complete packet.

## INFP core records

INFP-10 and INFP-11 share the same header shape. Their selector, total core
length, plaintext length, and ciphertext length differ.

### INFP-10 core

The INFP-10 core is exactly 128 bytes:

| Offset | Size | Field | Encoding or value |
| ---: | ---: | --- | --- |
| 0 | 1 | Selector | `0x10` |
| 1 | 4 | Magic | ASCII `INFP` |
| 5 | 4 | `key_id` | Session identifier |
| 9 | 8 | `iv` | AES-CTR IV prefix |
| 17 | 2 | Plaintext length | Little-endian `109` (`0x006d`) |
| 19 | 109 | Ciphertext | AES-128-CTR encrypted INFP-10 plaintext |

### INFP-11 core

The INFP-11 core is exactly 160 bytes:

| Offset | Size | Field | Encoding or value |
| ---: | ---: | --- | --- |
| 0 | 1 | Selector | `0x11` |
| 1 | 4 | Magic | ASCII `INFP` |
| 5 | 4 | `key_id` | Session identifier |
| 9 | 8 | `iv` | AES-CTR IV prefix |
| 17 | 2 | Plaintext length | Little-endian `141` (`0x008d`) |
| 19 | 141 | Ciphertext | AES-128-CTR encrypted INFP-11 plaintext |

## INFP-10 plaintext

The decrypted INFP-10 plaintext is exactly 109 bytes:

| Offset | Size | Field | Encoding and scale |
| ---: | ---: | --- | --- |
| 0 | 1 | Selector | Must be `0x10` |
| 1 | 1 | Version | Observed values `2` and `3` |
| 2 | 2 | Sequence | Unsigned little-endian |
| 4 | 2 | State flags | Unsigned little-endian bit field |
| 6 | 16 | Aircraft identifier | NUL-terminated or NUL-padded ASCII |
| 22 | 4 | Aircraft longitude | Signed little-endian radians × 10,000,000 |
| 26 | 4 | Aircraft latitude | Signed little-endian radians × 10,000,000 |
| 30 | 2 | Altitude | Signed little-endian metres |
| 32 | 2 | Relative height | Signed little-endian decimetres |
| 34 | 2 | North velocity | Signed little-endian centimetres/second |
| 36 | 2 | East velocity | Signed little-endian centimetres/second |
| 38 | 2 | Up velocity | Signed little-endian centimetres/second |
| 40 | 2 | Heading | Signed little-endian centidegrees |
| 42 | 8 | GPS time | Unsigned little-endian milliseconds |
| 50 | 4 | Application latitude | Signed little-endian radians × 10,000,000 |
| 54 | 4 | Application longitude | Signed little-endian radians × 10,000,000 |
| 58 | 4 | Home longitude | Signed little-endian radians × 10,000,000 |
| 62 | 4 | Home latitude | Signed little-endian radians × 10,000,000 |
| 66 | 1 | Product type | Unsigned identifier |
| 67 | 1 | DJI identity length | Unsigned; maximum 20 |
| 68 | 20 | DJI identity slot | UTF-8; use the declared prefix |
| 88 | 1 | DJI account ID length | Unsigned; maximum 20 |
| 89 | 20 | DJI account ID slot | UTF-8; use the declared prefix |

Convert coordinate fields using:

```text
degrees = raw / 10,000,000 × 180 / pi
```

Convert the scaled motion fields using:

```text
relative_height_metres = raw / 10
velocity_metres_per_second = raw / 100
heading_degrees = raw / 100
```

The unavailable-home-position sentinel is the pair:

```text
home_longitude_raw = 1,000,000,000
home_latitude_raw  = 1,000,000,000
```

Test the raw pair before coordinate conversion.

### INFP-10 state flags

The state word assigns the following names. A bit is set when
`state_flags & (1 << bit)` is nonzero.

| Bit | Name |
| ---: | --- |
| 0 | `unk0` |
| 1 | `aircraftIdentifierValid` |
| 2 | `uuidValid2` |
| 3 | `unk3` |
| 4 | `motorsOn` |
| 5 | `inAir` |
| 6 | `aircraftPositionValid` |
| 7 | `absoluteHeightValid` |
| 8 | `relativeHeightValid` |
| 9 | `horizontalVelocityValid` |
| 10 | `verticalVelocityValid` |
| 11 | `yawValid` |
| 12 | `appPositionValid` |
| 13 | `uuidValid13` |
| 14 | `unk14` |
| 15 | `unk15` |

Retain the complete 16-bit value. Names beginning with `unk` have no assigned
meaning. A field governed by a validity flag is unavailable when that flag is
clear.

### INFP-10 semantic validation

After structural validation and decryption, apply these checks:

- The plaintext selector is `0x10`.
- The plaintext length is 109 bytes.
- Version is `2` or `3`.
- Each variable text length is at most 20 bytes.
- Aircraft and application longitude are within `[-180, 180]` degrees.
- Aircraft and application latitude are within `[-90, 90]` degrees.
- Home coordinates are either the unavailable sentinel pair or valid longitude
  and latitude values.
- Heading is within `[-180, 180]` degrees.
- The combination of zero GPS time, zero aircraft longitude, and zero aircraft
  latitude may be rejected as an uninitialised record.
- The aircraft identifier, when surfaced as valid text, is non-empty ASCII
  alphanumeric.

A JSON implementation may reject GPS millisecond values above
`2^53 - 1` when it cannot preserve larger integers exactly.

## INFP-11 plaintext

The decrypted INFP-11 plaintext is exactly 141 bytes:

| Offset | Size | Field | Encoding or value |
| ---: | ---: | --- | --- |
| 0 | 1 | Selector | Must be `0x11` |
| 1 | 16 | Aircraft identifier | NUL-terminated or NUL-padded ASCII |
| 17 | 3 | Format marker | Must be `cc aa 03` |
| 20 | 1 | Purpose length | Unsigned; maximum 120 |
| 21 | 120 | Purpose slot | UTF-8; use the declared prefix |

The marker's final byte is the version value `3`.

Validate the selector, exact 141-byte length, three-byte marker, and purpose
bound before accepting the record. The aircraft identifier follows the same
validation rule as the other plaintext layouts.

## Receiver processing algorithm

The following pseudocode gives the complete normal receiver path:

```text
sessions = map from 4-byte key_id to 16-byte K

for each input record:
    core = remove_and_validate_envelope(record)
    packet = parse_core(core)

    if packet is CRYP:
        require packet.length == 163
        require packet.magic == "CRYP"
        require packet.ciphertext_length == 32

        C1 = decode_affine_point(packet.C1_x, packet.C1_y)
        require C1 is a valid non-infinity SM2 point

        S = d * C1
        require S is not the point at infinity
        (x2, y2) = encode_affine_coordinates(S, 32-byte big-endian)

        t = SM3(x2 || y2 || 00000001)[0:16]
        K = packet.C2 XOR t

        require constant_time_equal(
            SM3(x2 || K || y2),
            packet.C3
        )
        require constant_time_equal(
            SHA-256(K)[0:4],
            packet.key_id
        )

        sessions[packet.key_id] = K
        counter = packet.iv || (0x00 * 8)
        auxiliary = AES-128-CTR(K, counter, packet.ciphertext)
        validate_and_parse_cryp_auxiliary(auxiliary)

    if packet is INFP:
        require packet.magic == "INFP"
        require sessions contains packet.key_id
        K = sessions[packet.key_id]

        counter = packet.iv || (0x00 * 8)
        plaintext = AES-128-CTR(K, counter, packet.ciphertext)

        require plaintext[0] == packet.selector
        if packet.selector == 0x10:
            validate_and_parse_infp10(plaintext)
        else if packet.selector == 0x11:
            validate_and_parse_infp11(plaintext)
        else:
            reject
```

## Validation failures

Reject a record when any applicable condition below is true:

- Reject an unrecognised selector, magic value, core length, or internal length.
- Reject an envelope with a bad CRC rather than attempting to repair it
  implicitly.
- Reject an invalid or off-curve `C1` before scalar multiplication.
- Reject a CRYP record if either `C3` or `key_id` validation fails.
- Do not retain or use a candidate session key from a rejected CRYP record.
- Do not decrypt an INFP record without an authenticated key for its exact
  `key_id`.
- Reject decrypted INFP data whose selector or structural constants do not
  match the enclosing record.
- Treat reserved and unknown fields as opaque and preserve them when forwarding
  or re-encoding records.

## Product type identifiers

The product identifier list is known but not published.
