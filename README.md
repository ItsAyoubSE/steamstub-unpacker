# steamstub-unpacker

A small, self-contained unpacker for **SteamStub DRM Variant 2.1 (x86 / PE32)**,
written in Rust.

It locates the DRM stub, decodes the header and payload, decrypts
`SteamDRMP.dll`, restores the original encrypted code section and rebuilds a
working executable with the `.bind` section removed.

No external tools (Steamless, Ghidra, IDA, etc.) are used at build or run time.

## Features

- Detects SteamStub by the `.bind` section and the `C0DEC0DE` entry marker
- Finds the stub header by disassembling the entry stub (`iced-x86`)
- XOR-decodes the stub header and payload
- XTEA-decrypts the embedded `SteamDRMP.dll`
- Scans the DRM offset table (with the same fallback patterns as the reference
  unpacker)
- AES-CBC decrypts the main code section (rebuilt IV + stolen first block)
- Restores the original entry point, drops `.bind`, truncates the DRM blob
- Leaves no runtime payload behind — the output runs without the stub

## Usage

```text
steamstub-unpacker.exe <input.exe> [output.exe]
```

If `output.exe` is omitted, the result is written next to the input as
`<input.exe>.unpacked.exe`.

Example:

```powershell
.\steamstub-unpacker.exe "C:\Games\SomeGame\game.exe"
# -> C:\Games\SomeGame\game.exe.unpacked.exe
```

Back up your original executable and replace it with the unpacked one only
after confirming it runs.

## Build

Requires a recent stable Rust toolchain (MSVC).

```powershell
cargo build --release
```

Output: `target\release\steamstub-unpacker.exe`

## How it works

1. Parse the PE32 header and locate `.bind`.
2. Verify `0xC0DEC0DE` immediately before `AddressOfEntryPoint`.
3. Disassemble the entry stub to recover the header RVA, size and XOR key.
4. XOR-decode the header (rolling key), parse the Variant 2.1 layout.
5. XOR-decode the payload and read the embedded `SteamDRMP.dll` metadata.
6. XTEA-decrypt `SteamDRMP.dll` and locate the 8-entry DRM offset table.
7. Use the offsets to obtain flags, OEP, code-section VA, encrypted size,
   AES key, IV and stolen block.
8. AES-CBC decrypt the code section and write it back.
9. Patch `AddressOfEntryPoint`, zero the checksum, recompute `SizeOfImage`,
   remove the `.bind` section header and truncate the file.
10. Write the unpacked executable.

## Limitations

- Targets SteamStub **Variant 2.1 x86** only (32-bit PE32 with a `.bind`
  section). Other variants use different header/decryption formats.
- The file must use a regular `.bind` layout; heavily modified stubs may fail
  the signature checks.
- Intended for binaries you own and are allowed to modify.

## Disclaimer

Provided for research and interoperability purposes only. You are responsible
for complying with applicable laws, license agreements and terms of service.
