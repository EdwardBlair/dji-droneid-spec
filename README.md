# DJI DroneID CRYP/INFP specification

This repository documents the CRYP and INFP packet formats and provides a
Python reference implementation for encoding, encryption, framing, parsing,
decryption, and validation.

The reference implementation also packs and unpacks the O4 PHY's exact
173-byte payload plus three-byte CRC-24A. The PHY always consumes 173 bytes;
encoders leave the seven logical-object padding bytes and the remaining slot
bytes zero. An implementation that does not initialize the complete slot can
disclose stale memory in the unused tail. See `SPEC.md` under “O4 PHY transport
block.”

Given schema-compatible source data and a recipient public key, the
implementation constructs CRYP and INFP packets.

## Validate with an already-unwrapped session key

```sh
uv run python droneid.py \
  packets.txt \
  --session-key-hex 00112233445566778899aabbccddeeff
```

The 16-byte AES session key is an external input. The command checks its
four-byte key identifier, decrypts the CRYP auxiliary and associated INFP
payloads, and validates their schemas. It does not discover or unwrap the key.
For CRYP, the output marks `sm2C3` as `notChecked`: authenticating that field
requires the SM2 shared point, which the AES key and public key do not provide.

## Example keypair

The repository stores an example pair in `keys/` for the end-to-end
transmitter/receiver test. Its private scalar is `1`.

```sh
uv run python droneid.py \
  --dummy-example \
  --private-key-file keys/dummy_sm2_private_key.hex \
  --public-key-file keys/dummy_sm2_public_key.hex
```

See `SPEC.md` for the packet layouts and algorithms.

## Tests

```sh
uv run python -m unittest discover -s tests
uv run ruff check .
```
