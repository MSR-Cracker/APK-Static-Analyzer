"""Synthetic Multi-DEX APK generator for automated testing and validation of APK-Static-Analyzer."""
import os
import sys
import struct
import zipfile
import argparse


def build_minimal_dex(class_name: str, method_name: str, ret_type: str = "Z", extra_strings: list = None) -> bytes:
    """Builds a structurally valid minimal DEX binary with the given class, method, and strings."""
    if extra_strings is None:
        extra_strings = []

    all_strings = sorted(list(set([
        f"L{class_name.replace('.', '/')};",
        method_name,
        ret_type,
        "V",
        "()V",
        f"(){ret_type}",
        "<init>",
        "Ljava/lang/Object;",
    ] + extra_strings)))

    # String data buffer
    str_data = bytearray()
    str_offsets = []
    for s in all_strings:
        str_offsets.append(len(str_data))
        # uleb128 length + utf8 + null
        str_data.append(len(s))
        str_data.extend(s.encode("utf-8"))
        str_data.append(0)

    # Calculate offsets
    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(all_strings)

    type_ids_off = string_ids_off + string_ids_size * 4
    # Types: 0: Class, 1: RetType, 2: Void, 3: Object
    type_strings = [f"L{class_name.replace('.', '/')};", ret_type, "V", "Ljava/lang/Object;"]
    type_ids_size = len(type_strings)

    proto_ids_off = type_ids_off + type_ids_size * 4
    proto_ids_size = 2  # ()V, ()ret_type

    field_ids_off = proto_ids_off + proto_ids_size * 12
    field_ids_size = 0

    method_ids_off = field_ids_off
    # Methods: <init>()V, method()ret_type
    method_ids_size = 2

    class_defs_off = method_ids_off + method_ids_size * 8
    class_defs_size = 1

    data_off = class_defs_off + class_defs_size * 32

    # String IDs
    str_ids_bytes = bytearray()
    for off in str_offsets:
        str_ids_bytes.extend(struct.pack("<I", data_off + off))

    # Type IDs
    type_ids_bytes = bytearray()
    for ts in type_strings:
        idx = all_strings.index(ts)
        type_ids_bytes.extend(struct.pack("<I", idx))

    # Proto IDs: (shorty_idx, return_type_idx, parameters_off=0)
    proto_ids_bytes = bytearray()
    # 0: ()V
    proto_ids_bytes.extend(struct.pack("<III", all_strings.index("V"), type_strings.index("V"), 0))
    # 1: ()ret_type
    proto_ids_bytes.extend(struct.pack("<III", all_strings.index(ret_type), type_strings.index(ret_type), 0))

    # Method IDs: (class_idx, proto_idx, name_idx)
    method_ids_bytes = bytearray()
    # 0: <init>()V
    method_ids_bytes.extend(struct.pack("<HHI", 0, 0, all_strings.index("<init>")))
    # 1: method_name()ret_type
    method_ids_bytes.extend(struct.pack("<HHI", 0, 1, all_strings.index(method_name)))

    # Class Defs: (class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off)
    class_data_offset_in_data = len(str_data)
    class_defs_bytes = struct.pack(
        "<IIIIIIII",
        0, 1, 3, 0, 0, 0, data_off + class_data_offset_in_data, 0
    )

    # Class data item
    # static_fields=0, instance_fields=0, direct_methods=1 (<init>), virtual_methods=1
    class_data = bytearray([0, 0, 1, 1])
    # direct method: method_idx_diff=0, access=1, code_off=0
    class_data.extend([0, 1, 0])
    # virtual method: method_idx_diff=1, access=1, code_off=0
    class_data.extend([1, 1, 0])

    full_data = str_data + class_data
    total_size = data_off + len(full_data)

    # DEX Header
    header = bytearray(b"dex\n035\x00")
    header.extend(struct.pack("<I", 0))  # checksum
    header.extend(b"\x00" * 20)  # signature
    header.extend(struct.pack("<I", total_size))
    header.extend(struct.pack("<I", header_size))
    header.extend(struct.pack("<I", 0x12345678))  # endian
    header.extend(struct.pack("<II", 0, 0))  # link
    header.extend(struct.pack("<I", 0))  # map
    header.extend(struct.pack("<II", string_ids_size, string_ids_off))
    header.extend(struct.pack("<II", type_ids_size, type_ids_off))
    header.extend(struct.pack("<II", proto_ids_size, proto_ids_off))
    header.extend(struct.pack("<II", field_ids_size, field_ids_off))
    header.extend(struct.pack("<II", method_ids_size, method_ids_off))
    header.extend(struct.pack("<II", class_defs_size, class_defs_off))
    header.extend(struct.pack("<II", len(full_data), data_off))

    return bytes(header + str_ids_bytes + type_ids_bytes + proto_ids_bytes + method_ids_bytes + class_defs_bytes + full_data)


def create_synthetic_apk(output_path: str):
    """Creates a sample multi-DEX APK with billing and verification methods."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # DEX 1: Main Application
    dex1 = build_minimal_dex(
        "com.example.app.MainActivity",
        "onCreate",
        "V",
        ["com.example.billing.PurchaseManager", "is_premium"]
    )

    # DEX 2: BillingClient Library simulation
    dex2 = build_minimal_dex(
        "com.android.billingclient.api.BillingClient",
        "queryPurchasesAsync",
        "V",
        ["BillingResult", "PurchasesUpdatedListener", "acknowledgePurchase"]
    )

    # DEX 3: PurchaseManager with isPurchased()Z and remote verify URL
    dex3 = build_minimal_dex(
        "com.example.billing.PurchaseManager",
        "isPurchased",
        "Z",
        [
            "is_purchased", "sku_pro_access",
            "https://api.example.com/subscription/verify",
            "https://billing.example.com/v1/receipts"
        ]
    )

    # Binary AndroidManifest.xml mock
    manifest_bytes = b"\x03\x00\x08\x00" + b"\x00" * 40 + b"package\x00com.example.targetapp\x00android.permission.INTERNET\x00com.android.vending.BILLING\x00com.example.app.MainActivity\x00"

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest_bytes)
        z.writestr("classes.dex", dex1)
        z.writestr("classes2.dex", dex2)
        z.writestr("classes3.dex", dex3)
        z.writestr("META-INF/CERT.RSA", b"CERTIFICATE_MOCK_DATA")

    print(f"Created synthetic test APK at: {output_path} ({os.path.getsize(output_path)} bytes)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create synthetic test APK")
    parser.add_argument("--output", default="tests/sample_target.apk", help="Output APK path")
    args = parser.parse_args()
    create_synthetic_apk(args.output)
