# steamstub-unpacker

A small, self-contained unpacker for **SteamStub DRM Variant 2.0 and 2.1
(x86 / PE32)**, written in Rust.

It locates the DRM stub, decodes the header (and payload for 2.1), decrypts the
protected code section and rebuilds a working executable with the `.bind`
section removed.

No external tools (Steamless, Ghidra, IDA, etc.) are used at build or run time.

## Features

- Detects SteamStub by the `.bind` section and the `C0DEC0DE` entry marker
- Auto-detects the stub generation from the entry signature
- Finds the stub header by disassembling the entry stub (`iced-x86`)
- XOR-decodes the stub header
- **Variant 2.0:** XOR-decodes the code section (rolling dword key)
- **Variant 2.1:** XOR-decodes the payload, XTEA-decrypts `SteamDRMP.dll`,
  scans the DRM offset table, AES-CBC decrypts the code section
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
3. Pick the variant from the entry stub opcode (`C7` = 2.1, `BE` = 2.0).
4. Disassemble the entry stub to recover the header RVA and size.
5. XOR-decode the header and parse the matching layout.

Variant 2.0:

6. Read flags, OEP, code-section size and XOR key from the header.
7. XOR-decode the code section with its rolling dword key.

Variant 2.1:

6. XOR-decode the payload and read the embedded `SteamDRMP.dll` metadata.
7. XTEA-decrypt `SteamDRMP.dll` and locate the 8-entry DRM offset table.
8. Use the offsets to obtain flags, OEP, code-section VA, encrypted size,
   AES key, IV and stolen block.
9. AES-CBC decrypt the code section.

Both variants:

10. Patch `AddressOfEntryPoint`, zero the checksum, recompute `SizeOfImage`,
    remove the `.bind` section header and truncate the file.
11. Write the unpacked executable.

## Limitations

- Targets SteamStub **Variant 2.0 / 2.1 x86** only (32-bit PE32 with a `.bind`
  section). Other variants (1.x, 3.x, x64) use different formats.
- The file must use a regular `.bind` layout; heavily modified stubs may fail
  the signature checks.
- Intended for binaries you own and are allowed to modify.

## Disclaimer

Provided for research and interoperability purposes only. You are responsible
for complying with applicable laws, license agreements and terms of service.
