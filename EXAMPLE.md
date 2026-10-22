# CRYP/INFP reference implementation examples

## Construct packets with extracted recipient public material

```sh
uv run python droneid.py \
  --public-key-file /path/to/recipient_public_key.hex \
  --encrypt-example
```

Compatible recipient public material is not included. It can be extracted from
firmware from a supported device. The input file is either 64 raw bytes or 128
hexadecimal characters containing the 32-byte big-endian X coordinate followed
by the 32-byte big-endian Y coordinate.

The command constructs a new CRYP/INFP session using that supplied public point
and newly generated cryptographic values.

## Validate with an unwrapped session key

```sh
uv run python droneid.py \
  packets.txt \
  --session-key-hex 00112233445566778899aabbccddeeff
```

The 16-byte AES session key is an external input. The command checks its
four-byte key identifier, decrypts the CRYP auxiliary and associated INFP
payloads, and validates their schemas. It does not discover or unwrap the key.
For CRYP, the output marks `sm2C3` as `notChecked` because that calculation also
requires the SM2 shared point.

## Example keypair and round trip

The example private scalar is `d = 1`, so the public point is the standard SM2
generator `G`.

```text
d  = 0000000000000000000000000000000000000000000000000000000000000001
Qx = 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Qy = BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
```

The values are stored in `keys/dummy_sm2_private_key.hex` and
`keys/dummy_sm2_public_key.hex`.

Run the complete CRYP, INFP-10, and INFP-11 round trip:

```sh
uv run python droneid.py \
  --dummy-example \
  --private-key-file keys/dummy_sm2_private_key.hex \
  --public-key-file keys/dummy_sm2_public_key.hex
```

The same flow through the Python API:

```python
from pathlib import Path

from droneid import (
    build_cryp_core,
    build_infp_core,
    coordinate_to_raw,
    decrypt_packet_payload,
    encode_cryp_plaintext,
    encode_infp11_plaintext,
    load_private_key,
    load_public_key,
    parse_packet,
    recover_session_key,
)

private_key = load_private_key(Path("keys/dummy_sm2_private_key.hex"))
public_key = load_public_key(Path("keys/dummy_sm2_public_key.hex"))
session_key = bytes.fromhex("00112233445566778899aabbccddeeff")

cryp_plaintext = encode_cryp_plaintext(
    aircraft_identifier="DUMMYAIRCRAFT01",
    longitude_raw=coordinate_to_raw(-0.1278),
    latitude_raw=coordinate_to_raw(51.5074),
)
cryp_core = build_cryp_core(
    session_key,
    public_key,
    cryp_plaintext,
    bytes.fromhex("0001020304050607"),
)

infp_plaintext = encode_infp11_plaintext(
    aircraft_identifier="DUMMYAIRCRAFT01",
    purpose="TEST-ONLY EXAMPLE",
)
infp_core = build_infp_core(
    session_key,
    infp_plaintext,
    bytes.fromhex("1011121314151617"),
)

cryp_packet = parse_packet(cryp_core)
recovered_key = recover_session_key(cryp_packet, private_key)
assert recovered_key == session_key

decoded_cryp = decrypt_packet_payload(cryp_packet, recovered_key)
decoded_infp = decrypt_packet_payload(parse_packet(infp_core), recovered_key)
assert decoded_cryp["aircraftIdentifier"] == "DUMMYAIRCRAFT01"
assert decoded_infp["purpose"] == "TEST-ONLY EXAMPLE"
```

## Tests

```sh
uv run python -m unittest discover -s tests
uv run ruff check .
```
