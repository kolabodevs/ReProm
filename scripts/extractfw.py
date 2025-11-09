import argparse, struct, hashlib, binascii, ast, sys, os

def calc_checksum(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF

def calc_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest().upper()

def calc_crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF

# This function search for the chip model and firmware date
def decode_header(data: bytes):
    # Promontory chip list and it's firmware max size
    chip_info = [
        (b"3306A_FW", "Prom", 0x20000),
        (b"3306B_FW", "PromLP", 0x20000),
        (b"3308A_FW", "Prom19", 0x20000),
        (b"3328A_FW", "Prom21", 0x20000)
    ]
    
    fw_date, fw_size, chip_model = "UNKNOWN", "UNKNOWN", "UNKNOWN"
    for signature, model, max_size in chip_info:
        if signature in data:
            chip_model = model
            fw_size = max_size
            try:
                year = data[0x8C]
                month = data[0x8D]
                day = data[0x8E]
                version0 = data[0x8F]
                version1 = data[0x90]
                version2 = data[0x91]
                fw_date = f"{year:02X}{month:02X}{day:02X}_{version0:02X}_{version1:02X}_{version2:02X}"
            except IndexError:
                fw_date = "Invalid date"
            break
    return chip_model, fw_date, fw_size

# This function will generate the header part for firmware loading via SPI NOR Flash, This is not required if the firmware is loaded via PCIe MMIO
def generate_header(chip_model: str, custom_info: str, xdata: list) -> bytes:
    # Promontory marketing names and it's device ID
    chip_info = [
        ("Prom",   b"3306A_RCFG"),
        ("PromLP", b"3306B_RCFG"),
        ("Prom19", b"3308A_RCFG"),
        ("Prom21", b"3328A_RCFG")
    ]
    for signature, hexbits in chip_info:
        if chip_model in signature:
            header = bytes([0, 0, 1, 0, 255, 255]) + hexbits
            break

    if custom_info:
        if len(custom_info) > 16:
            print(f"Info: Custom information is too long, trimming to 16 characters.")
        custom_info = custom_info[:16]
        header += custom_info.encode('ascii')
        padding = (16 - len(header) % 16) % 16
        if padding:
            header += bytes(padding)
        header += bytes(16)

    cleaned_xdata = []
    for index, (addr_str, val_str) in enumerate(xdata):
        try:
            addr = int(addr_str, 16)
            val = int(val_str, 16)
            if addr > 0xFFFF or val > 0xFFFFFFFF:
                print(f"Warning: Invalid Address: {hex(addr)} or Value: {hex(val)}, Ignored")
                continue
            cleaned_xdata.append([addr, val])
        except ValueError:
            print(f"Warning: Non-hex input at index {index}: Address='{addr_str}', Value='{val_str}', Ignored")

    if cleaned_xdata:
        if not custom_info:
            header += bytes(32)
        for addr, val in cleaned_xdata:
            hex_len = len(f"{val:X}")
            if hex_len == 3:
                data_length = 2
            else:
                data_length = (hex_len + 1) // 2
            header += b"\xCC"
            header += bytes.fromhex(f"0{data_length}")
            header += struct.pack('<H', addr)
            if data_length == 4:
                header += struct.pack('<I', val)
            elif data_length == 2:
                header += struct.pack('<H', val)
            else:
                header += struct.pack('<B', val)
            pad_len = (8 - len(header) % 8) % 8
            if pad_len:
                header += bytes(pad_len)

    header = header[:4] + struct.pack('<H', len(header)) + header[6:]
    checksum = bytes([sum(header) & 0xFF])
    crc32 = struct.pack('<I', calc_crc32(header))
    return header + checksum + crc32

# This function extract RAW firmware without AGESA's header and PSP's HMAC signature
def extract_firmware(data: bytes, output_dir: str, ignore_checksum: bool, spi_mode: bool, custom_info: str, xdata: list, seen_hashes: set) -> int:
    extracted_count = 0
    offset = 0

    while offset < len(data):
        # Search for the AGESA _PT_ header
        pos = data.find(b"_PT_", offset)
        if pos == -1:
            break

        if pos + 12 > len(data):
            offset = pos + 1
            continue

        length = struct.unpack_from("<I", data, pos + 4)[0]
        if length < 12 or pos + length > len(data):
            offset = pos + 1
            continue

        fw_data = data[pos:pos + length]
        fw_pos = f"0x{pos:X}"
        fw_type, fw_ver, fw_size = decode_header(fw_data)
        size = len(fw_data[0xC:0xC + fw_size]) if fw_size != "UNKNOWN" else len(fw_data[0xC:])
        fw_hash = calc_md5(fw_data[0xC:0xC + size])

        end = length & 0xFFFFFF00
        header_checksum = struct.unpack_from("<I", data, pos + 8)[0]
        checksum = calc_checksum(fw_data[0xC:end])
        is_valid = ignore_checksum or header_checksum == checksum

        # Check if calculated checksum match with the embedded checksum in AGESA header
        if is_valid:
            # Check if the firmware has been extracted before, 600/800 series motherboard's UEFI image contain multiple Prom FW 
            if fw_hash in seen_hashes:
                print(f"|-- Found {fw_type} firmware at {fw_pos}\n|  |- This firmware has been extracted before, in the same file or batch of files, skipping extraction.\n|")
                offset = pos + length
                continue
            # Check if SPI header moded enabled.
            if spi_mode and fw_type != "UNKNOWN":
                chip_info = [
                    ("Prom",   b"3306A_FW"),
                    ("PromLP", b"3306B_FW"),
                    ("Prom19", b"3308A_FW"),
                    ("Prom21", b"3328A_FW")
                ]
                for signature, hexbits in chip_info:
                    if fw_type in signature:
                        footer = hexbits
                        break
                try:
                    header = generate_header(fw_type, custom_info, xdata)
                    body_size = struct.pack('<I', int(size - 0x13 - len(header)))
                    body_checksum = struct.pack('<I', checksum)
                    crc32 = struct.pack('<I', calc_crc32(fw_data[0xC:0xC + int(size - 0x13 - len(header))]))
                    fw_data = header + body_size + fw_data[0xC:0xC + int(size - 0x13 - len(header))] + footer + body_checksum[:1] + crc32
                    padding = (16 - len(fw_data) % 16) % 16
                    if padding:
                        fw_data += b'\xFF' * padding
                except Exception as e:
                    print(f"Error: Failed to add header: {e}")
                    offset = pos + length
                    continue
            elif spi_mode:
                print(f"Error: Unable to add SPI header, because:\n a. The firmware is corrupted\n b. The chipset is a newly released and unsupported model.")
                spi_mode = False
            else:
                fw_data = fw_data[0xC:0xC + size]

            # Determine file name by mode and checksum
            if header_checksum == checksum and spi_mode:
                # Checksum good, SPI header mode
                filename = f"{fw_type.upper()}_SPI_{fw_ver}_CHKGD_{fw_hash}.bin"
            elif header_checksum == checksum and not spi_mode:
                # Checksum good, RAW extraction mode
                filename = f"{fw_type.upper()}_RAW_{fw_ver}_CHKGD_{fw_hash}.bin"
            elif header_checksum != checksum and spi_mode:
                # Checksum BAD, SPI header mode
                filename = f"{fw_type.upper()}_SPI_{fw_ver}_CHKNG_{fw_hash}.bin"
            else:
                # Checksum BAD, Raw extraction mode
                filename = f"{fw_type.upper()}_RAW_{fw_ver}_CHKNG_{fw_hash}.bin"

            status_msg = "Firmware has been extracted to" if header_checksum == checksum else "Firmware with BAD checksum has been extracted to"
            print(f"|-- Found {fw_type} firmware at {fw_pos}\n|  |- Size: 0x{size:X}\n|  |- Version: {fw_ver}\n|  |- MD5: {fw_hash}\n|  |- {status_msg}: {filename}\n|")
            # Create dir if dir not exists
            os.makedirs(output_dir, exist_ok=True)
            # Write output file
            with open(os.path.join(output_dir, filename), "wb") as fw_file:
                fw_file.write(fw_data)

            seen_hashes.add(fw_hash)
            extracted_count += 1
        else:
            print(f"|-- Found {fw_type} firmware at {fw_pos} with bad checksum\n|  |- Expected: 0x{header_checksum:X}, Got: 0x{checksum:X}\n|  |- Skipping extraction. Use --ignore-checksum to force extraction.\n|")

        offset = pos + length

    return extracted_count

# This function loads UEFI images
def process_file(filepath: str, output_dir: str, ignore_checksum: bool, spi_mode: bool, write_custom: str, write_xdata: str, seen_hashes: set) -> int:
    try:
        with open(filepath, "rb") as file:
            data = file.read()
    except FileNotFoundError:
        print(f"Error: Cannot open file '{filepath}'.", file=sys.stderr)
        return 0

    xdata_list = []
    if write_xdata:
        try:
            xdata_list = ast.literal_eval(write_xdata)
            if not isinstance(xdata_list, list):
                raise ValueError("write_xdata is not a list")
        except Exception as e:
            print(f"Error parsing --write-xdata: {e}", file=sys.stderr)
            return 0

    return extract_firmware(data, output_dir, ignore_checksum, spi_mode, write_custom, xdata_list, seen_hashes)

# This function read command line args
def main() -> int:
    parser = argparse.ArgumentParser(description="Extract Promontory firmware in UEFI images.")
    parser.add_argument("-f", "--input-file", help="Path to a single UEFI binary image file.")
    parser.add_argument("-d", "--input-directory", help="Directory containing UEFI binary image files.")
    parser.add_argument("-o", "--output-directory", default="extracted", help="Directory for saving the extracted firmware.")
    parser.add_argument("-i", "--ignore-checksum", action="store_true", help="Extract firmware even if checksum does not match.")
    parser.add_argument("-wh", "--write-header", action="store_true", help="Advanced: Add header to extracted firmware for SPI loading")
    parser.add_argument("-wc", "--write-custom", help="Advanced: Add custom string to firmware header (up to 16 ASCII chars).")
    parser.add_argument("-wx", "--write-xdata", help="Advanced: Add config(s) to header, Value must in HEX format, Example: -wx \"[['0xFFFF', 'FFFF'], ['$Address', '$Value']]\"")
    args = parser.parse_args()

    total_extracted = 0
    seen_hashes = set()

    if args.write_custom and not args.write_header:
        args.write_header = True
        print(f"Info: --write-custom is specified, --write-header has been enabled automatically")
    if args.write_xdata and not args.write_header:
        args.write_header = True
        print(f"Info: --write-xdata is specified, --write-header has been enabled automatically")
            
    if args.input_directory:
        if not os.path.isdir(args.input_directory):
            print(f"Error: '{args.input_directory}' is not a valid directory.", file=sys.stderr)
            return 1

        for file in os.listdir(args.input_directory):
            full_path = os.path.join(args.input_directory, file)
            if os.path.isfile(full_path):
                print(f"\nProcessing: {file}")
                total_extracted += process_file(full_path, args.output_directory, args.ignore_checksum, args.write_header, args.write_custom, args.write_xdata, seen_hashes)

    elif args.input_file:
        print(f"\nProcessing: {args.input_file}")
        total_extracted += process_file(args.input_file, args.output_directory, args.ignore_checksum, args.write_header, args.write_custom, args.write_xdata, seen_hashes)

    else:
        print(f"Error: You must specify either --input-file or --input-directory.", file=sys.stderr)
        return 1

    if total_extracted > 0:
        print(f"\nInfo: Successfully extracted {total_extracted} unique firmware image(s).")
        return 0
    else:
        print(f"\nInfo: No valid firmware images were found.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
