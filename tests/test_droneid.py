from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from droneid import (
    SM2_G,
    build_cryp_core,
    coordinate_to_raw,
    decode_cryp_plaintext,
    decode_file_with_session_key,
    dummy_round_trip,
    encode_cryp_plaintext,
    generate_iv,
    generate_keypair,
    generate_session_key,
    load_private_key,
    load_public_key,
    parse_packet,
    pack_transport_block,
    public_key_from_private,
    recover_session_key,
    unpack_transport_block,
    wrap_logical_object,
)

ROOT = Path(__file__).resolve().parents[1]
DUMMY_PRIVATE_KEY = load_private_key(ROOT / "keys" / "dummy_sm2_private_key.hex")
DUMMY_PUBLIC_KEY = load_public_key(ROOT / "keys" / "dummy_sm2_public_key.hex")


class PrivateKeyCrypDecoderTests(unittest.TestCase):
    def test_dummy_pair_is_deliberately_trivial(self) -> None:
        self.assertEqual(DUMMY_PRIVATE_KEY, 1)
        self.assertEqual(DUMMY_PUBLIC_KEY, SM2_G)
        self.assertEqual(
            public_key_from_private(DUMMY_PRIVATE_KEY),
            DUMMY_PUBLIC_KEY,
        )

    def test_production_generators_return_valid_sizes_and_keypair(self) -> None:
        private_key, public_key = generate_keypair()

        self.assertEqual(public_key_from_private(private_key), public_key)
        self.assertEqual(len(generate_session_key()), 16)
        self.assertEqual(len(generate_iv()), 8)

    def test_complete_dummy_transmitter_receiver_round_trip(self) -> None:
        result = dummy_round_trip(DUMMY_PRIVATE_KEY, DUMMY_PUBLIC_KEY)

        self.assertIn("private key d=1", result["example"])
        self.assertEqual(
            result["decodedCryp"]["aircraftIdentifier"],
            "DUMMYAIRCRAFT01",
        )
        self.assertEqual(result["decodedInfp10"]["sequence"], 1)
        self.assertEqual(
            result["decodedInfp11"]["purpose"],
            "TEST-ONLY EXAMPLE",
        )

    def test_default_sm2_wrapping_uses_fresh_randomness(self) -> None:
        session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
        plaintext = encode_cryp_plaintext(
            aircraft_identifier="DUMMYAIRCRAFT01",
            longitude_raw=coordinate_to_raw(-0.1278),
            latitude_raw=coordinate_to_raw(51.5074),
        )
        first = build_cryp_core(
            session_key,
            DUMMY_PUBLIC_KEY,
            plaintext,
            bytes(8),
        )
        second = build_cryp_core(
            session_key,
            DUMMY_PUBLIC_KEY,
            plaintext,
            bytes(8),
        )

        self.assertNotEqual(parse_packet(first).c1, parse_packet(second).c1)
        self.assertEqual(
            recover_session_key(parse_packet(first), DUMMY_PRIVATE_KEY),
            session_key,
        )

    def test_known_session_key_validates_without_private_key(self) -> None:
        session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
        plaintext = encode_cryp_plaintext(
            aircraft_identifier="DUMMYAIRCRAFT01",
            longitude_raw=coordinate_to_raw(-0.1278),
            latitude_raw=coordinate_to_raw(51.5074),
        )
        core = build_cryp_core(
            session_key,
            DUMMY_PUBLIC_KEY,
            plaintext,
            bytes.fromhex("0001020304050607"),
        )
        with tempfile.TemporaryDirectory() as directory:
            packets = Path(directory) / "packets.txt"
            packets.write_text(core.hex() + "\n")
            result = decode_file_with_session_key(packets, session_key)

        self.assertEqual(result[0]["droneId"]["aircraftIdentifier"], "DUMMYAIRCRAFT01")
        self.assertTrue(result[0]["validation"]["keyIdentifier"])
        self.assertEqual(result[0]["validation"]["sm2C3"], "notChecked")

    def test_logical_envelope_preserves_a_generated_core(self) -> None:
        result = dummy_round_trip(DUMMY_PRIVATE_KEY, DUMMY_PUBLIC_KEY)
        core = bytes.fromhex(result["crypCoreHex"])
        direct = parse_packet(core)
        logical = parse_packet(wrap_logical_object(core, bytes(7)))

        self.assertEqual(logical, direct)

    def test_real_l1c2_block_preserves_but_does_not_standardise_slot_residue(self) -> None:
        raw = bytes.fromhex(
            "8710494e4650fcf6ec7263c310cc5f7061ed6d0052b180e7d2a20fe67a1bf117"
            "2ae25d1f6c4e557044d2b2bd9669c48f46ec91f21207670fddef5602c79ce7b4"
            "ff0dec18d18d1b0215f8e79617f42a2f238ac2d835d6d711d87f1965890402cb"
            "dc02009a4c2d95f28192bdf4848080c11f5c7574f1f279d08d47136300f0a818"
            "775a2000586480e3195700000000000000000000000000000000000000000000"
            "000000000000000000ac18bbd3ba98e2"
        )
        decoded = unpack_transport_block(raw)
        self.assertEqual(len(decoded.logical_object), 138)
        self.assertEqual(decoded.object_padding.hex(), "5a2000586480e3")
        self.assertIn(bytes.fromhex("ac18bbd3"), decoded.slot_tail)
        self.assertEqual(
            pack_transport_block(
                decoded.core,
                object_padding=decoded.object_padding,
                slot_template=decoded.payload,
            ),
            raw,
        )
        generated = unpack_transport_block(pack_transport_block(decoded.core))
        self.assertEqual(generated.core, decoded.core)
        self.assertNotIn(bytes.fromhex("ac18bbd3"), generated.slot_tail)

    def test_decodes_complete_cryp_auxiliary_layout(self) -> None:
        plaintext = (
            b"F986425C100ST1EL"
            + (19_892_214).to_bytes(4, "little", signed=True)
            + (3_941_258).to_bytes(4, "little", signed=True)
            + b"\x03"
            + bytes(7)
        )
        decoded = decode_cryp_plaintext(plaintext)
        self.assertEqual(decoded["aircraftIdentifier"], "F986425C100ST1EL")
        self.assertEqual(decoded["positionValidityFlags"], 3)
        self.assertTrue(decoded["aircraftPositionValid"])
        self.assertTrue(decoded["positionProducerMarker"])
        self.assertEqual(decoded["reservedHex"], "00000000000000")


if __name__ == "__main__":
    unittest.main()
