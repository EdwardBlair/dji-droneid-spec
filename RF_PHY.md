# DroneID RF and PHY Specification

[中文](RF_PHY_CN.md)

## Scope

This document specifies the RF channel sequence, OFDM waveform, forward-error
correction, and passive demodulation needed to recover the 173-byte transport
block that carries the logical objects defined in [`README.md`](README.md).

It describes a receiver. Hardware-specific tuning corrections, gain settings,
sample formats, and transmitter scheduling are outside its scope. A timing or
reference-sequence correlation is only a candidate detection; a receiver must
complete FEC and all applicable integrity and structural checks before
accepting a packet.

## RF channel sequence

The receive sequence uses these seven RF centres:

```text
2414.5, 2429.5, 2444.5, 5756.5, 5776.5, 5796.5, 5816.5 MHz
```

Packets are nominally separated by 640 ms. Let `c` be the unsigned eight-bit
publication counter associated with a publication. This counter is schedule
state, not a field carried in the decoded packet. The channel for that counter
is:

```text
r = (c + 255) mod 256
i = (r + 6) mod 7
frequency_mhz = [2429.5, 2444.5, 5756.5, 5776.5,
                 5796.5, 5816.5, 2414.5][i]
```

The modulo-256 operation is performed before the modulo-seven operation. This
matters at counter wrap. The complete counter cycle lasts
`256 * 0.640 s = 163.84 s`.

The counter-to-channel relationship supports passive predictive reception.
During acquisition, cover the seven centres either concurrently or by scanning
until a packet passes the complete validation chain. Treat its publication as
ordinal zero and initialize 256 hypotheses, one for each possible counter
value. For each later publication ordinal `p`, a hypothesis `h` predicts the
channel obtained from `c = (h + p) mod 256`. Remove hypotheses inconsistent
with integrity-valid channel observations. A missed observation may remove a
hypothesis only when the receiver had settled, continuous coverage of the
channel and complete expected publication window that it predicted.

Once one hypothesis remains, the receiver can predict subsequent channels and
retune before each nominal publication. It must return to acquisition after
loss of timing or phase confidence. Channel phase alone does not identify or
authenticate a source.

The table contains ideal RF centres. Any frequency correction required by a
particular oscillator or receiver belongs to that receiver's calibration and
must not be treated as part of the channel definition.

## OFDM waveform

| Property | Value |
| --- | ---: |
| Native complex sample rate | 15.36 MS/s |
| FFT length | 1,024 |
| Subcarrier spacing | 15 kHz |
| Symbols per packet | 8 |
| Cyclic-prefix lengths, symbols 0–7 | `80, 72, 72, 72, 72, 72, 72, 80` samples |
| Packet extent | 8,784 complex samples |
| Occupied subcarriers | `-300..-1, +1..+300` |
| Data modulation | QPSK |

DC is unused. With FFT-shifted indexing over a 1,024-element vector, occupied
bins are `212..511` and `513..812`.

The symbol allocation is:

| Symbol | Contents |
| ---: | --- |
| 0 | 600 QPSK data subcarriers |
| 1 | 600 QPSK data subcarriers |
| 2 | root-600 reference |
| 3 | 600 QPSK data subcarriers |
| 4 | root-147 reference |
| 5 | 600 QPSK data subcarriers |
| 6 | 600 QPSK data subcarriers |
| 7 | 600 QPSK data subcarriers |

The useful-symbol starts, measured from the start of the first cyclic prefix,
are:

```text
80, 1176, 2272, 3368, 4464, 5560, 6656, 7760
```

Each data symbol carries 1,200 coded bits. The six data symbols therefore carry
7,200 coded bits. Adjacent bits `(bI, bQ)` map to:

```text
((1 - 2*bI) + j*(1 - 2*bQ)) / sqrt(2)
```

Thus bit zero selects the positive component and bit one selects the negative
component.

### Reference sequences

Both references occupy the same 600 non-DC subcarriers as the data. For output
index `m` in `0..599`, define:

```text
n = m              when m < 300
n = m - 600        when m >= 300
```

The symbol-2 reference is:

```text
R600[m] = exp(j * pi * n * (n + 1) / 601)
```

The symbol-4 reference is:

```text
R147[m] = exp(-j * pi * 147 * n * (n + 1) / 601)
```

Symbol 2 provides the channel estimate. Symbol 4 supplies an additional
reference check but is not required to construct that estimate.

## Channel coding

The PHY input is exactly 173 bytes. Bit ordering within each byte is most
significant bit first.

### CRC-24A

Append a three-byte big-endian CRC-24A remainder to the 173-byte input, giving
176 bytes or 1,408 bits. The register starts at zero, has no final XOR, and is
updated most-significant bit first with polynomial `0x864cfb` (the low 24 bits
of `0x1864cfb`). A correctly completed 176-byte block has zero remainder.

### Turbo code and rate matching

Use the terminated LTE turbo code with input size `K = 1408`. Its QPP
interleaver is:

```text
pi(i) = (43*i + 88*i*i) mod 1408
```

The two eight-state constituent encoders begin in state zero and are each
terminated to state zero with three tail inputs. For state bits
`(r0, r1, r2)` and input `u`:

```text
internal = u XOR r2 XOR r1
parity   = r2 XOR r0 XOR internal
new_state = (internal, r0, r1)
```

For each input bit, emit systematic, first-parity, and second-parity bits. The
tail outputs add 12 bits, producing 4,236 turbo bits in total.

Apply the LTE 32-column sub-block interleaver and circular-buffer rate matcher
with `D = 1412`, redundancy version `RV = 0`, and output length `E = 7200`.
The column permutation is:

```text
0,16,8,24,4,20,12,28,2,18,10,26,6,22,14,30,
1,17,9,25,5,21,13,29,3,19,11,27,7,23,15,31
```

For these parameters the interleaver has 45 rows, 1,440 positions per stream,
and 28 leading null positions. Circular selection starts at position 90,
skips null positions, wraps as necessary, and stops after 7,200 bits.

### Scrambling

XOR the 7,200 rate-matched bits with the LTE Gold sequence using
`c_init = 0x12345678` and `Nc = 1600`.

Initialize `x1(0) = 1`, all other initial `x1` bits to zero, and initialize
`x2(0)..x2(30)` from bits 0 through 30 of `c_init`, least-significant bit
first. Generate:

```text
x1(n + 31) = x1(n + 3) XOR x1(n)
x2(n + 31) = x2(n + 3) XOR x2(n + 2) XOR x2(n + 1) XOR x2(n)
c(n) = x1(n + 1600) XOR x2(n + 1600)
```

The scrambled bit is `e(n) XOR c(n)`. The initializer is fixed PHY material,
not a secret or a packet field.

## Passive demodulation

A conforming receiver can use the following pipeline:

1. Acquire one of the seven RF centres and convert the selected channel to
   complex baseband. Resample to 15.36 MS/s if necessary.
2. Locate eight-symbol candidates by correlating each cyclic prefix with the
   end of its 1,024-sample useful symbol. Use all eight expected symbol
   positions when ranking a candidate.
3. Estimate fractional carrier-frequency offset from the aggregate cyclic-
   prefix phase. Cyclic-prefix estimation leaves an integer-subcarrier
   ambiguity; test offsets in 15 kHz steps and select the hypothesis with the
   strongest QPSK consistency and valid downstream decoding.
4. Remove cyclic prefixes, correct the selected frequency offset, and take a
   1,024-point FFT for every symbol.
5. Extract the 600 occupied subcarriers. Divide symbol 2 by `R600` to estimate
   the channel, smooth that estimate across nearby subcarriers if required,
   and equalize data symbols `0, 1, 3, 5, 6, 7`.
6. Form signed soft values from the real and imaginary components in carrier
   order. In the convention used here, positive soft values represent bit one.
7. Undo the Gold scrambling, reverse RV-0 rate matching, and turbo-decode the
   1,408-bit block.
8. Require a zero CRC-24A remainder. Parse the first 173 bytes as a logical
   object and then require its declared boundary, inner CRC-16, selector,
   marker, exact core length, and type-specific structure to be valid.
9. Only after those checks may the packet update the passive channel follower
   or be passed to the CRYP/INFP processing described in `README.md`.

Detection thresholds, channel-estimator smoothing width, turbo-decoder
iteration count, and oscillator tracking are receiver-quality choices. They do
not change the wire format. A receiver must not replace packet integrity checks
with correlation or constellation-score thresholds.

## PHY implementation verification task

The task is to implement the forward PHY described above and reproduce the
SHA-256 values in the table below:

1. Construct the 173-byte input `00 01 02 ... ac`; byte `i` has value `i`.
2. Process that input through CRC-24A, turbo encoding, rate matching,
   scrambling, QPSK mapping, and OFDM modulation exactly as specified.
3. At each boundary listed in the table, serialize the complete result using
   the rules below and calculate its SHA-256 digest.
4. Compare the calculated digest with the published value. A matching digest
   means the complete output at that boundary is identical to the reference
   output. The first mismatch identifies the stage that differs.

The hashes are expected results, not input files. No pre-generated waveform is
included. This verification input contains no captured packet or private
material and is not a valid typed CRYP or INFP object.

Before hashing a bit vector, pack it most-significant bit first into bytes.
Serialize a complex vector as interleaved real and imaginary IEEE-754 binary32
values in little-endian order. Serialize frequency symbols in symbol-major,
FFT-shifted-bin order.

| Boundary | Length | SHA-256 |
| --- | ---: | --- |
| Input transport | 173 bytes | `73b1f1000c7677ebdcef2a2a25e27b06d9c163209add77a16f0e2b70e56d5c52` |
| Transport plus CRC-24A | 176 bytes | `20c3bd6bfc7522ce2eecdc77589acb63419846e031df19a62861dbf272ff93cd` |
| Turbo output | 4,236 bits | `12bbea41da53fbffa35038d3243d6e6b56e53fe595a3f88364f2f100a1fc6760` |
| Rate-matched output | 7,200 bits | `2a1cdb2ca6304982af40f019da93fd0170843171feb9aeb1def1025f8a6f9f06` |
| Scrambled output | 7,200 bits | `8a70e028f3fe6f2bda8cea2ae6b3ec239d41619a390a8fe633b3f2f119c4355a` |
| Eight frequency-domain symbols | 8 x 1,024 complex values | `3b1867eb0d8b8b9400cbca4cb2e91aa0e3359b182f6c2a637f9840d25ab91301` |
| Complete time-domain packet | 8,784 complex values | `70578e11d9ddbc8ce1e27e0b3fe74de8fcaa445e32e5aca1e673cf0cf7bd88ad` |

As additional checks, the appended CRC bytes are `b6 a0 38`. The first 32
rate-matched bits are `00110011001100110011001100110011`; after scrambling
they are `11100001110100101110110101001010`.
