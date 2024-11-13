"""Script to decrypt the base64 & XOR encrypted TCP streams"""

import sys
import base64


def xor_crypt(data: bytes, key: bytes) -> bytes:
    """Function to XOR data using a key"""

    key_length = len(key)
    encrypted_data = []

    for i, byte in enumerate(data):
        encrypted_byte = byte ^ key[i % key_length]
        encrypted_data.append(encrypted_byte)

    return bytes(encrypted_data)


def main() -> None:
    """Main driver function"""

    key = "MySup3rXoRKeYForCommandandControl".encode("utf-8")

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} stream.txt output.txt")
        sys.exit(1)

    with open(sys.argv[1], 'r', encoding='utf-8') as input_file:
        tcp_streams = input_file.readlines()

    output_streams = []
    for stream in tcp_streams:
        encoded_command = stream.split("AAAAAAAAAA")[1]
        decrypted_command = xor_crypt(base64.b64decode(encoded_command), key)
        output_streams.append(decrypted_command.decode("utf-8") + "\n")

    with open(sys.argv[2], 'w', encoding='utf-8') as output_file:
        output_file.writelines(output_streams)


if __name__ == '__main__':
    main()
