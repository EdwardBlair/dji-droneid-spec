#!/usr/bin/env python3
"""Reference DJI O4 DroneID CRYP/INFP transmitter and receiver.

The implementation uses the conventional recipient SM2 private/public key
path. It constructs and parses CRYP and INFP records, wraps and unwraps the AES
session key, encrypts and decrypts payloads, and validates their plaintext
layouts. It contains no alternate key-discovery mechanism.

In decode mode, the input file contains one hexadecimal packet per line. Supply
either a recipient SM2 private-key file for complete CRYP authentication or an
already-unwrapped AES session key for payload validation. The private-key file
may contain either a 32-byte binary scalar or its 64-character hex form.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_G = (
    0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
)

Point = tuple[int, int]

STATE_FLAG_NAMES = (
    "unk0", "aircraftIdentifierValid", "uuidValid2", "unk3",
    "motorsOn", "inAir", "aircraftPositionValid", "absoluteHeightValid",
    "relativeHeightValid", "horizontalVelocityValid", "verticalVelocityValid", "yawValid",
    "appPositionValid", "uuidValid13", "unk14", "unk15",
)


def decode_state_flags(value: int) -> dict[str, Any]:
    return {
        "hex": f"{value:04x}",
        "set": [
            name
            for bit, name in enumerate(STATE_FLAG_NAMES)
            if value & (1 << bit)
        ],
    }


class PacketError(ValueError):
    pass


@dataclass(frozen=True)
class Packet:
    kind: str
    key_id: bytes
    selector: int | None = None
    c1: bytes | None = None
    c2: bytes | None = None
    c3: bytes | None = None
    iv: bytes | None = None
    ciphertext: bytes | None = None


@dataclass(frozen=True)
class WrappedSessionKey:
    c1: bytes
    c2: bytes
    c3: bytes
    key_id: bytes


def inverse(value: int) -> int:
    return pow(value, SM2_P - 2, SM2_P)


def on_curve(point: Point) -> bool:
    x, y = point
    return (
        0 <= x < SM2_P
        and 0 <= y < SM2_P
        and (y * y - (x * x * x + SM2_A * x + SM2_B)) % SM2_P == 0
    )


def point_add(left: Point | None, right: Point | None) -> Point | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % SM2_P == 0:
            return None
        slope = (3 * x1 * x1 + SM2_A) * inverse(2 * y1 % SM2_P) % SM2_P
    else:
        slope = (y2 - y1) * inverse((x2 - x1) % SM2_P) % SM2_P
    x3 = (slope * slope - x1 - x2) % SM2_P
    return x3, (slope * (x1 - x3) - y1) % SM2_P


def scalar_multiply(scalar: int, point: Point) -> Point | None:
    result = None
    addend: Point | None = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def validate_private_key(private_key: int) -> None:
    if not isinstance(private_key, int) or not 1 <= private_key < SM2_N:
        raise ValueError("SM2 private scalar is outside [1, n - 1]")


def generate_private_key() -> int:
    return secrets.randbelow(SM2_N - 1) + 1


def generate_keypair() -> tuple[int, Point]:
    private_key = generate_private_key()
    return private_key, public_key_from_private(private_key)


def generate_session_key() -> bytes:
    return secrets.token_bytes(16)


def generate_iv() -> bytes:
    return secrets.token_bytes(8)


def validate_public_key(public_key: Point) -> None:
    if not on_curve(public_key):
        raise ValueError("SM2 public key is not a valid curve point")


def public_key_from_private(private_key: int) -> Point:
    validate_private_key(private_key)
    public_key = scalar_multiply(private_key, SM2_G)
    if public_key is None:  # pragma: no cover - excluded by scalar validation
        raise ValueError("SM2 public key is the point at infinity")
    return public_key


def encode_point(point: Point) -> bytes:
    validate_public_key(point)
    return point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def decode_point(encoded: bytes) -> Point:
    if len(encoded) != 64:
        raise ValueError("SM2 affine point must contain exactly 64 bytes")
    point = (
        int.from_bytes(encoded[:32], "big"),
        int.from_bytes(encoded[32:], "big"),
    )
    validate_public_key(point)
    return point


def require_bytes(name: str, value: bytes, length: int) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{name} must contain exactly {length} bytes")


def crc8(data: bytes, initial: int = 0x77) -> int:
    value = initial
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ 0x8C if value & 1 else value >> 1
    return value & 0xFF


def crc16(data: bytes, initial: int = 0x3692) -> int:
    value = initial
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ 0x8408 if value & 1 else value >> 1
    return value & 0xFFFF


def wrap_logical_object(core: bytes, padding: bytes = b"") -> bytes:
    if direct_core(core) != core:
        raise ValueError("logical object requires one complete CRYP or INFP core")
    payload = core + padding
    if len(payload) > 0xFF:
        raise ValueError("logical-object payload exceeds its one-byte length")
    framed = bytes((len(payload),)) + payload
    return framed + crc16(framed).to_bytes(2, "little")


def wrap_v1_frame(
    core: bytes,
    *,
    transport_metadata: bytes = bytes(5),
    length_flags: int = 0,
) -> bytes:
    if direct_core(core) != core:
        raise ValueError("V1 frame requires one complete CRYP or INFP core")
    require_bytes("V1 transport metadata", transport_metadata, 5)
    if not 0 <= length_flags <= 0xFC or length_flags & 0x03:
        raise ValueError("V1 length flags may use only bits 2 through 7")
    total = 13 + len(core)
    if total > 0x3FF:
        raise ValueError("V1 frame exceeds its ten-bit declared length")
    prefix = bytes((0x55, total & 0xFF, length_flags | (total >> 8)))
    framed = prefix + bytes((crc8(prefix),)) + transport_metadata + b"\x03\xda" + core
    return framed + crc16(framed).to_bytes(2, "little")


def direct_core(data: bytes) -> bytes | None:
    lengths = {0x10: 128, 0x11: 160, 0x13: 163}
    length = lengths.get(data[0]) if data else None
    magic = b"CRYP" if data and data[0] == 0x13 else b"INFP"
    if length is None or len(data) < length or data[1:5] != magic:
        return None
    return data[:length]


def unwrap(data: bytes) -> bytes:
    core = direct_core(data)
    if core is not None:
        return core

    if len(data) >= 4 and data[0] + 3 <= len(data):
        raw = data[: data[0] + 3]
        if crc16(raw[:-2]) == int.from_bytes(raw[-2:], "little"):
            core = direct_core(raw[1:-2])
            if core is not None:
                return core

    if len(data) >= 13 and data[0] == 0x55:
        declared = data[1] | ((data[2] & 3) << 8)
        if declared == len(data) and data[3] == crc8(data[:3]):
            if data[9:11] != b"\x03\xda":
                raise PacketError("V1 frame is not a DroneID service packet")
            if crc16(data[:-2]) != int.from_bytes(data[-2:], "little"):
                raise PacketError("V1 frame CRC is invalid")
            core = direct_core(data[11:-2])
            if core is not None:
                return core

    raise PacketError("unrecognised packet envelope or invalid CRC")


def parse_packet(data: bytes) -> Packet:
    core = unwrap(data)
    if core[0] == 0x13:
        if core[129:131] != b"\x20\x00":
            raise PacketError("invalid CRYP layout")
        return Packet(
            kind="CRYP",
            key_id=core[5:9],
            c1=core[9:73],
            c3=core[73:105],
            c2=core[105:121],
            iv=core[121:129],
            ciphertext=core[131:163],
        )

    selector = core[0]
    expected = {0x10: 109, 0x11: 141}.get(selector)
    if expected is None or core[17:19] != expected.to_bytes(2, "little"):
        raise PacketError("invalid INFP layout")
    return Packet(
        kind=f"INFP-{selector:02X}",
        key_id=core[5:9],
        selector=selector,
        iv=core[9:17],
        ciphertext=core[19:],
    )


def sm3(data: bytes) -> bytes:
    try:
        return hashlib.new("sm3", data).digest()
    except ValueError as error:
        raise RuntimeError("this Python/OpenSSL build does not provide SM3") from error


def sm2_mask(shared: Point) -> bytes:
    shared_x = shared[0].to_bytes(32, "big")
    shared_y = shared[1].to_bytes(32, "big")
    return sm3(shared_x + shared_y + b"\0\0\0\1")[:16]


def wrap_session_key(
    session_key: bytes,
    recipient_public_key: Point,
) -> WrappedSessionKey:
    """Wrap one AES key using conventional SM2 encryption."""

    require_bytes("AES session key", session_key, 16)
    validate_public_key(recipient_public_key)

    while True:
        scalar = generate_private_key()
        c1_point = scalar_multiply(scalar, SM2_G)
        shared = scalar_multiply(scalar, recipient_public_key)
        if c1_point is None or shared is None:  # pragma: no cover - SM2 cofactor is one
            raise ValueError("SM2 multiplication produced the point at infinity")
        mask = sm2_mask(shared)
        if any(mask):
            break

    shared_x = shared[0].to_bytes(32, "big")
    shared_y = shared[1].to_bytes(32, "big")
    return WrappedSessionKey(
        c1=encode_point(c1_point),
        c2=bytes(a ^ b for a, b in zip(session_key, mask)),
        c3=sm3(shared_x + session_key + shared_y),
        key_id=hashlib.sha256(session_key).digest()[:4],
    )


def recover_session_key(packet: Packet, private_key: int) -> bytes:
    if packet.kind != "CRYP" or None in (packet.c1, packet.c2, packet.c3):
        raise PacketError("a complete CRYP packet is required")
    try:
        validate_private_key(private_key)
        require_bytes("CRYP C2", packet.c2 or b"", 16)
        require_bytes("CRYP C3", packet.c3 or b"", 32)
        require_bytes("CRYP key identifier", packet.key_id, 4)
        point = decode_point(packet.c1 or b"")
    except ValueError as error:
        raise PacketError(str(error)) from error
    shared = scalar_multiply(private_key, point)
    if shared is None:
        raise PacketError("CRYP shared point is at infinity")
    shared_x = shared[0].to_bytes(32, "big")
    shared_y = shared[1].to_bytes(32, "big")
    mask = sm2_mask(shared)
    key = bytes(a ^ b for a, b in zip(packet.c2 or b"", mask))
    expected_c3 = sm3(shared_x + key + shared_y)
    if not hmac.compare_digest(expected_c3, packet.c3 or b""):
        raise PacketError(
            "CRYP C3 validation failed (wrong private key or corrupt packet)"
        )
    if not hmac.compare_digest(hashlib.sha256(key).digest()[:4], packet.key_id):
        raise PacketError("CRYP key identifier validation failed")
    return key


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    require_bytes("AES session key", key, 16)
    require_bytes("AES-CTR IV prefix", iv, 8)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv + b"\0" * 8))
    transform = cipher.encryptor()
    return transform.update(data) + transform.finalize()


def text(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def coordinate(value: bytes) -> float:
    raw = int.from_bytes(value, "little", signed=True)
    return raw / 10_000_000 * 180 / math.pi


def coordinate_to_raw(degrees: float) -> int:
    if not math.isfinite(degrees):
        raise ValueError("coordinate must be finite")
    raw = round(degrees * math.pi / 180 * 10_000_000)
    if not -(1 << 31) <= raw < (1 << 31):
        raise ValueError("coordinate does not fit a signed 32-bit word")
    return raw


def encode_integer(name: str, value: int, size: int, *, signed: bool) -> bytes:
    if not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    try:
        return value.to_bytes(size, "little", signed=signed)
    except OverflowError as error:
        kind = "signed" if signed else "unsigned"
        raise ValueError(f"{name} does not fit a {size * 8}-bit {kind} integer") from error


def encode_aircraft_identifier(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("aircraft identifier must be ASCII") from error
    if not encoded or len(encoded) > 16 or not encoded.isalnum():
        raise ValueError("aircraft identifier must be 1-16 ASCII alphanumeric bytes")
    return encoded.ljust(16, b"\0")


def encode_utf8_slot(name: str, value: str, size: int) -> tuple[bytes, bytes]:
    encoded = value.encode("utf-8")
    if len(encoded) > size:
        raise ValueError(f"{name} exceeds its {size}-byte UTF-8 slot")
    return bytes((len(encoded),)), encoded.ljust(size, b"\0")


def encode_cryp_plaintext(
    *,
    aircraft_identifier: str,
    longitude_raw: int,
    latitude_raw: int,
    position_validity_flags: int = 0x03,
    reserved: bytes = bytes(7),
) -> bytes:
    if not 0 <= position_validity_flags <= 0xFF:
        raise ValueError("CRYP position-validity flags must fit one byte")
    require_bytes("CRYP reserved field", reserved, 7)
    plaintext = (
        encode_aircraft_identifier(aircraft_identifier)
        + encode_integer("CRYP longitude", longitude_raw, 4, signed=True)
        + encode_integer("CRYP latitude", latitude_raw, 4, signed=True)
        + bytes((position_validity_flags,))
        + reserved
    )
    decode_cryp_plaintext(plaintext)
    return plaintext


def encode_infp10_plaintext(
    *,
    aircraft_identifier: str,
    version: int = 3,
    sequence: int = 0,
    state_flags: int = 0,
    aircraft_longitude_raw: int = 0,
    aircraft_latitude_raw: int = 0,
    altitude_m: int = 0,
    relative_height_dm: int = 0,
    velocity_north_cms: int = 0,
    velocity_east_cms: int = 0,
    velocity_up_cms: int = 0,
    heading_centidegrees: int = 0,
    gps_time_ms: int = 1,
    app_latitude_raw: int = 0,
    app_longitude_raw: int = 0,
    home_longitude_raw: int = 1_000_000_000,
    home_latitude_raw: int = 1_000_000_000,
    product_type: int = 0,
    dji_identity: str = "",
    dji_account_id: str = "",
) -> bytes:
    if version not in (2, 3):
        raise ValueError("INFP-10 version must be 2 or 3")
    if not 0 <= product_type <= 0xFF:
        raise ValueError("INFP-10 product type must fit one byte")
    identity_length, identity_slot = encode_utf8_slot("DJI identity", dji_identity, 20)
    account_length, account_slot = encode_utf8_slot("DJI account ID", dji_account_id, 20)
    plaintext = b"".join(
        (
            b"\x10",
            bytes((version,)),
            encode_integer("INFP-10 sequence", sequence, 2, signed=False),
            encode_integer("INFP-10 state flags", state_flags, 2, signed=False),
            encode_aircraft_identifier(aircraft_identifier),
            encode_integer("aircraft longitude", aircraft_longitude_raw, 4, signed=True),
            encode_integer("aircraft latitude", aircraft_latitude_raw, 4, signed=True),
            encode_integer("altitude", altitude_m, 2, signed=True),
            encode_integer("relative height", relative_height_dm, 2, signed=True),
            encode_integer("north velocity", velocity_north_cms, 2, signed=True),
            encode_integer("east velocity", velocity_east_cms, 2, signed=True),
            encode_integer("up velocity", velocity_up_cms, 2, signed=True),
            encode_integer("heading", heading_centidegrees, 2, signed=True),
            encode_integer("GPS time", gps_time_ms, 8, signed=False),
            encode_integer("application latitude", app_latitude_raw, 4, signed=True),
            encode_integer("application longitude", app_longitude_raw, 4, signed=True),
            encode_integer("home longitude", home_longitude_raw, 4, signed=True),
            encode_integer("home latitude", home_latitude_raw, 4, signed=True),
            bytes((product_type,)),
            identity_length,
            identity_slot,
            account_length,
            account_slot,
        )
    )
    decode_plaintext(0x10, plaintext)
    return plaintext


def encode_infp11_plaintext(*, aircraft_identifier: str, purpose: str) -> bytes:
    purpose_length, purpose_slot = encode_utf8_slot("INFP-11 purpose", purpose, 120)
    plaintext = (
        b"\x11"
        + encode_aircraft_identifier(aircraft_identifier)
        + b"\xcc\xaa\x03"
        + purpose_length
        + purpose_slot
    )
    decode_plaintext(0x11, plaintext)
    return plaintext


def build_cryp_core(
    session_key: bytes,
    recipient_public_key: Point,
    auxiliary_plaintext: bytes,
    iv: bytes,
) -> bytes:
    decode_cryp_plaintext(auxiliary_plaintext)
    require_bytes("CRYP IV", iv, 8)
    wrapped = wrap_session_key(session_key, recipient_public_key)
    ciphertext = aes_ctr(session_key, iv, auxiliary_plaintext)
    return (
        b"\x13CRYP"
        + wrapped.key_id
        + wrapped.c1
        + wrapped.c3
        + wrapped.c2
        + iv
        + len(ciphertext).to_bytes(2, "little")
        + ciphertext
    )


def build_infp_core(session_key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    if not plaintext:
        raise ValueError("INFP plaintext is empty")
    selector = plaintext[0]
    expected = {0x10: 109, 0x11: 141}.get(selector)
    if expected is None or len(plaintext) != expected:
        raise ValueError("INFP plaintext selector or length is invalid")
    decode_plaintext(selector, plaintext)
    require_bytes("INFP IV", iv, 8)
    key_id = hashlib.sha256(session_key).digest()[:4]
    ciphertext = aes_ctr(session_key, iv, plaintext)
    return (
        bytes((selector,))
        + b"INFP"
        + key_id
        + iv
        + len(ciphertext).to_bytes(2, "little")
        + ciphertext
    )


def decode_cryp_plaintext(plain: bytes) -> dict[str, Any]:
    if len(plain) != 32:
        raise PacketError("decrypted CRYP auxiliary must contain exactly 32 bytes")
    longitude_raw = int.from_bytes(plain[16:20], "little", signed=True)
    latitude_raw = int.from_bytes(plain[20:24], "little", signed=True)
    position_validity_flags = plain[24]
    aircraft_position_valid = bool(position_validity_flags & 0x01)
    longitude = coordinate(plain[16:20])
    latitude = coordinate(plain[20:24])
    if aircraft_position_valid and (not -180 <= longitude <= 180 or not -90 <= latitude <= 90):
        raise PacketError("CRYP auxiliary coordinates are invalid")
    return {
        "aircraftIdentifier": text(plain[:16]),
        "longitudeRaw": longitude_raw,
        "latitudeRaw": latitude_raw,
        "longitude": longitude if aircraft_position_valid else None,
        "latitude": latitude if aircraft_position_valid else None,
        "positionValidityFlags": position_validity_flags,
        "aircraftPositionValid": aircraft_position_valid,
        "positionProducerMarker": bool(position_validity_flags & 0x02),
        "reservedHex": plain[25:32].hex(),
    }


def decode_plaintext(selector: int, plain: bytes) -> dict[str, Any]:
    if not plain or plain[0] != selector:
        raise PacketError("decrypted INFP selector does not match")
    if selector == 0x11:
        if len(plain) != 141 or plain[17:20] != b"\xcc\xaa\x03" or plain[20] > 120:
            raise PacketError("invalid decrypted INFP-11 layout")
        return {
            "aircraftIdentifier": text(plain[1:17]),
            "purpose": plain[21 : 21 + plain[20]].decode("utf-8", errors="replace"),
        }
    if len(plain) != 109 or plain[1] not in (2, 3) or plain[67] > 20 or plain[88] > 20:
        raise PacketError("invalid decrypted INFP-10 layout")

    def signed(start: int, size: int) -> int:
        return int.from_bytes(plain[start : start + size], "little", signed=True)

    return {
        "version": plain[1],
        "sequence": int.from_bytes(plain[2:4], "little"),
        "stateFlags": decode_state_flags(int.from_bytes(plain[4:6], "little")),
        "aircraftIdentifier": text(plain[6:22]),
        "aircraftLongitude": coordinate(plain[22:26]),
        "aircraftLatitude": coordinate(plain[26:30]),
        "altitudeM": signed(30, 2),
        "relativeHeightM": signed(32, 2) / 10,
        "velocityNorthMs": signed(34, 2) / 100,
        "velocityEastMs": signed(36, 2) / 100,
        "velocityUpMs": signed(38, 2) / 100,
        "headingDegrees": signed(40, 2) / 100,
        "gpsTimeMs": int.from_bytes(plain[42:50], "little"),
        "appLatitude": coordinate(plain[50:54]),
        "appLongitude": coordinate(plain[54:58]),
        "homeLongitude": coordinate(plain[58:62]),
        "homeLatitude": coordinate(plain[62:66]),
        "productType": plain[66],
        "djiIdentity": plain[68 : 68 + plain[67]].decode("utf-8", errors="replace"),
        "djiAccountId": plain[89 : 89 + plain[88]].decode("utf-8", errors="replace"),
    }


def decrypt_packet_payload(packet: Packet, session_key: bytes) -> dict[str, Any]:
    if packet.iv is None or packet.ciphertext is None:
        raise PacketError("packet has no encrypted payload")
    try:
        plaintext = aes_ctr(session_key, packet.iv, packet.ciphertext)
    except ValueError as error:
        raise PacketError(str(error)) from error
    if packet.kind == "CRYP":
        return decode_cryp_plaintext(plaintext)
    if packet.selector not in (0x10, 0x11):
        raise PacketError("unsupported INFP selector")
    return decode_plaintext(packet.selector, plaintext)


def load_private_key(path: Path) -> int:
    raw = path.read_bytes()
    if len(raw) == 32:
        encoded = raw
    else:
        value = raw.decode("ascii").strip()
        if value.lower().startswith("0x"):
            value = value[2:]
        try:
            encoded = bytes.fromhex(value)
        except ValueError as error:
            raise ValueError("private-key file is neither raw bytes nor hex") from error
    if len(encoded) != 32:
        raise ValueError("SM2 private scalar must be exactly 32 bytes")
    scalar = int.from_bytes(encoded, "big")
    if not 1 <= scalar < SM2_N:
        raise ValueError("SM2 private scalar is outside [1, n - 1]")
    return scalar


def load_public_key(path: Path) -> Point:
    raw = path.read_bytes()
    if len(raw) in (64, 65):
        encoded = raw
    else:
        value = "".join(raw.decode("ascii").split())
        if value.lower().startswith("0x"):
            value = value[2:]
        try:
            encoded = bytes.fromhex(value)
        except ValueError as error:
            raise ValueError("public-key file is neither raw bytes nor hex") from error
    if len(encoded) == 65 and encoded[0] == 0x04:
        encoded = encoded[1:]
    return decode_point(encoded)


def parse_session_key(value: str) -> bytes:
    if value.lower().startswith("0x"):
        value = value[2:]
    try:
        key = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("session key is not valid hexadecimal") from error
    require_bytes("AES session key", key, 16)
    return key


def packet_lines(path: Path) -> list[tuple[int, str]]:
    result = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        value = line.strip()
        if value:
            result.append((number, value))
    return result


def decrypt_file(path: Path, private_key: int, show_keys: bool) -> list[dict[str, Any]]:
    parsed: list[tuple[int, str, Packet | None, str | None]] = []
    for number, value in packet_lines(path):
        try:
            packet = parse_packet(bytes.fromhex(value))
            parsed.append((number, value, packet, None))
        except (PacketError, ValueError) as error:
            parsed.append((number, value, None, str(error)))

    sessions: dict[bytes, bytes] = {}
    cryp_errors: dict[bytes, str] = {}
    for _number, _value, packet, _error in parsed:
        if packet is not None and packet.kind == "CRYP":
            try:
                sessions[packet.key_id] = recover_session_key(packet, private_key)
            except PacketError as error:
                cryp_errors[packet.key_id] = str(error)

    output = []
    for number, value, packet, error in parsed:
        item: dict[str, Any] = {"line": number, "data": value, "droneId": None}
        if error is not None:
            item["error"] = error
        elif packet is not None:
            session_id = packet.key_id.hex()
            key = sessions.get(packet.key_id)
            if packet.kind == "CRYP":
                if key is None:
                    item["error"] = cryp_errors.get(
                        packet.key_id, "session recovery failed"
                    )
                else:
                    result = decrypt_packet_payload(packet, key)
                    result.update(packetType="CRYP", sessionId=session_id)
                    if show_keys:
                        result["sessionKey"] = key.hex()
                    item["droneId"] = result
            elif key is None:
                item["error"] = "no matching CRYP session key"
            else:
                try:
                    result = decrypt_packet_payload(packet, key)
                    result["packetType"] = packet.kind
                    result["sessionId"] = session_id
                    item["droneId"] = result
                except (PacketError, ValueError) as caught:
                    item["error"] = str(caught)
        output.append(item)
    return output


def decode_file_with_session_key(path: Path, session_key: bytes) -> list[dict[str, Any]]:
    """Decode packets when the 16-byte AES session key is already known.

    This validates the four-byte key identifier and payload structure. It does
    not validate the CRYP C3 value because that requires the SM2 shared point.
    """

    require_bytes("AES session key", session_key, 16)
    expected_key_id = hashlib.sha256(session_key).digest()[:4]
    output: list[dict[str, Any]] = []
    for number, value in packet_lines(path):
        item: dict[str, Any] = {"line": number, "data": value, "droneId": None}
        try:
            packet = parse_packet(bytes.fromhex(value))
            if not hmac.compare_digest(packet.key_id, expected_key_id):
                raise PacketError("packet key identifier does not match session key")
            decoded = decrypt_packet_payload(packet, session_key)
            decoded["packetType"] = packet.kind
            decoded["sessionId"] = packet.key_id.hex()
            item["droneId"] = decoded
            validation: dict[str, Any] = {
                "keyIdentifier": True,
                "payloadStructure": True,
            }
            if packet.kind == "CRYP":
                validation["sm2C3"] = "notChecked"
            item["validation"] = validation
        except (PacketError, ValueError) as error:
            item["error"] = str(error)
        output.append(item)
    return output


def public_key_encryption_example(recipient_public_key: Point) -> dict[str, Any]:
    """Construct a fresh CRYP/INFP example using only a recipient public key."""

    validate_public_key(recipient_public_key)
    session_key = generate_session_key()
    identifier = "PUBLICKEYDEMO01"
    cryp_plaintext = encode_cryp_plaintext(
        aircraft_identifier=identifier,
        longitude_raw=coordinate_to_raw(-0.1278),
        latitude_raw=coordinate_to_raw(51.5074),
    )
    infp10_plaintext = encode_infp10_plaintext(
        aircraft_identifier=identifier,
        sequence=1,
        state_flags=0x1FF2,
        aircraft_longitude_raw=coordinate_to_raw(-0.1278),
        aircraft_latitude_raw=coordinate_to_raw(51.5074),
        gps_time_ms=1_700_000_000_000,
        app_latitude_raw=coordinate_to_raw(51.5075),
        app_longitude_raw=coordinate_to_raw(-0.1277),
        home_latitude_raw=coordinate_to_raw(51.5074),
        home_longitude_raw=coordinate_to_raw(-0.1278),
        dji_identity="PUBLIC-KEY-DEMO",
    )
    infp11_plaintext = encode_infp11_plaintext(
        aircraft_identifier=identifier,
        purpose="PUBLIC-KEY ENCRYPTION DEMO",
    )
    cryp_core = build_cryp_core(
        session_key,
        recipient_public_key,
        cryp_plaintext,
        generate_iv(),
    )
    infp10_core = build_infp_core(session_key, infp10_plaintext, generate_iv())
    infp11_core = build_infp_core(session_key, infp11_plaintext, generate_iv())
    return {
        "note": (
            "Encryption uses only the recipient public key. Receiver-side SM2 "
            "unwrapping requires the corresponding private key."
        ),
        "recipientPublicKeyHex": encode_point(recipient_public_key).hex(),
        "sessionKeyHex": session_key.hex(),
        "crypCoreHex": cryp_core.hex(),
        "infp10CoreHex": infp10_core.hex(),
        "infp11CoreHex": infp11_core.hex(),
    }


def dummy_round_trip(private_key: int, public_key: Point) -> dict[str, Any]:
    """Build and decode a complete test-only CRYP/INFP session."""

    validate_private_key(private_key)
    validate_public_key(public_key)
    if public_key_from_private(private_key) != public_key:
        raise ValueError("dummy private and public key files do not form a keypair")

    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    identifier = "DUMMYAIRCRAFT01"
    cryp_plaintext = encode_cryp_plaintext(
        aircraft_identifier=identifier,
        longitude_raw=coordinate_to_raw(-0.1278),
        latitude_raw=coordinate_to_raw(51.5074),
    )
    infp10_plaintext = encode_infp10_plaintext(
        aircraft_identifier=identifier,
        sequence=1,
        state_flags=0x1FF2,
        aircraft_longitude_raw=coordinate_to_raw(-0.1278),
        aircraft_latitude_raw=coordinate_to_raw(51.5074),
        altitude_m=120,
        relative_height_dm=425,
        velocity_north_cms=125,
        velocity_east_cms=-50,
        heading_centidegrees=9000,
        gps_time_ms=1_700_000_000_000,
        app_latitude_raw=coordinate_to_raw(51.5075),
        app_longitude_raw=coordinate_to_raw(-0.1277),
        home_latitude_raw=coordinate_to_raw(51.5074),
        home_longitude_raw=coordinate_to_raw(-0.1278),
        product_type=66,
        dji_identity="DUMMY-ID",
        dji_account_id="DUMMY-ACCOUNT",
    )
    infp11_plaintext = encode_infp11_plaintext(
        aircraft_identifier=identifier,
        purpose="TEST-ONLY EXAMPLE",
    )

    cryp_core = build_cryp_core(
        session_key,
        public_key,
        cryp_plaintext,
        bytes.fromhex("0001020304050607"),
    )
    infp10_core = build_infp_core(
        session_key,
        infp10_plaintext,
        bytes.fromhex("1011121314151617"),
    )
    infp11_core = build_infp_core(
        session_key,
        infp11_plaintext,
        bytes.fromhex("2021222324252627"),
    )

    cryp_packet = parse_packet(cryp_core)
    recovered_key = recover_session_key(cryp_packet, private_key)
    if recovered_key != session_key:  # pragma: no cover - internal invariant
        raise AssertionError("dummy CRYP session-key round trip failed")
    infp10_packet = parse_packet(infp10_core)
    infp11_packet = parse_packet(infp11_core)

    return {
        "example": (
            "private key d=1, public key Q=G, fixed session key, and fixed IVs"
        ),
        "dummyPublicKeyHex": encode_point(public_key).hex(),
        "crypCoreHex": cryp_core.hex(),
        "infp10CoreHex": infp10_core.hex(),
        "infp11CoreHex": infp11_core.hex(),
        "decodedCryp": decrypt_packet_payload(cryp_packet, recovered_key),
        "decodedInfp10": decrypt_packet_payload(infp10_packet, recovered_key),
        "decodedInfp11": decrypt_packet_payload(infp11_packet, recovered_key),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "packets",
        nargs="?",
        type=Path,
        help="file containing one hex packet per line",
    )
    parser.add_argument(
        "--private-key-file",
        type=Path,
        help="32-byte raw or 64-character hex SM2 private scalar",
    )
    parser.add_argument(
        "--public-key-file",
        type=Path,
        help="64-byte raw or 128-character hex SM2 affine public point",
    )
    parser.add_argument(
        "--session-key-hex",
        help="known 16-byte AES key; validates key_id and payloads, not CRYP C3",
    )
    parser.add_argument(
        "--show-session-keys",
        action="store_true",
        help="include recovered AES session keys in CRYP output",
    )
    parser.add_argument(
        "--dummy-example",
        action="store_true",
        help="run the file-supplied example keypair end-to-end",
    )
    parser.add_argument(
        "--encrypt-example",
        action="store_true",
        help="construct fresh CRYP/INFP cores using --public-key-file",
    )
    args = parser.parse_args()
    if args.dummy_example:
        if args.private_key_file is None or args.public_key_file is None:
            parser.error(
                "--dummy-example requires --private-key-file and --public-key-file"
            )
        if args.packets is not None or args.session_key_hex is not None:
            parser.error("--dummy-example does not accept packet or session-key input")
        if args.encrypt_example or args.show_session_keys:
            parser.error("--dummy-example does not accept other mode flags")
        try:
            result = dummy_round_trip(
                load_private_key(args.private_key_file),
                load_public_key(args.public_key_file),
            )
        except (OSError, RuntimeError, UnicodeError, ValueError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        json.dump(result, sys.stdout, indent=2, separators=(",", ": "))
        print()
        return 0
    if args.encrypt_example:
        if args.public_key_file is None:
            parser.error("--encrypt-example requires --public-key-file")
        if any(
            value is not None
            for value in (args.packets, args.private_key_file, args.session_key_hex)
        ):
            parser.error("--encrypt-example accepts only --public-key-file")
        try:
            result = public_key_encryption_example(load_public_key(args.public_key_file))
        except (OSError, RuntimeError, UnicodeError, ValueError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        json.dump(result, sys.stdout, indent=2, separators=(",", ": "))
        print()
        return 0
    if args.public_key_file is not None:
        parser.error("--public-key-file is used only with --encrypt-example")
    if args.packets is None:
        parser.error("decode mode requires PACKETS")
    if (args.private_key_file is None) == (args.session_key_hex is None):
        parser.error(
            "decode mode requires exactly one of --private-key-file or "
            "--session-key-hex"
        )
    try:
        if args.private_key_file is not None:
            private_key = load_private_key(args.private_key_file)
            result = decrypt_file(args.packets, private_key, args.show_session_keys)
        else:
            if args.show_session_keys:
                parser.error("--show-session-keys requires --private-key-file")
            result = decode_file_with_session_key(
                args.packets,
                parse_session_key(args.session_key_hex or ""),
            )
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, indent=2, separators=(",", ": "))
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
