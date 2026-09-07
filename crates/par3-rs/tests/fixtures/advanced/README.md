# Advanced reference fixtures

PAR3 bytes come only from official par3cmdline runs at commit
`2971702e501f1350b1c7b9d11369af9157d6ed56`. The checked-in recipe is
`bench/rarpar-bench/internal/testcorpus/par3_advanced.go`.

The following records describe the initial reference runs. Original inputs
are damaged in memory by tests; PAR3 packet bytes are never edited.

## FFT generation record

```json
{
  "reference_commit": "2971702e501f1350b1c7b9d11369af9157d6ed56",
  "source_archive_blake3": "2989f64bcfff5ca14493ffa4e68dd058ab2b88236a9e64e884ac74387a225072",
  "command": [
    "par3",
    "c",
    "-s1024",
    "-e8",
    "-c8",
    "-cm16",
    "fft.par3",
    "input.bin"
  ],
  "input_recipe": "bytes((i * 73 + i // 29) % 256 for i in range(14000))",
  "files": {
    "fft.par3": "f2e7462ba8aa381a90887510c1d7904e2dc6000538179bd20abb9567102ece4f",
    "fft.vol0+1.par3": "7ddb4045fa7b3ad6b48da965f7f99b12e9efde6f128f15387889b416b4bec2ba",
    "fft.vol1+2.par3": "3f02db4ff98b39105e149e25161e87420f208f1b02239c7e5417dc75cfb939b1",
    "fft.vol3+4.par3": "5f3235fdc6219419b77aaccad4d353865683516d1b3e95cfe9bec88a24d29ec0",
    "fft.vol7+1.par3": "94424d4d32fe8d14a8e4bd3b6a931f8e5aa1013b89fbb6e695af45a9133c7f42",
    "fft16.par3": "2af5543d1494dc9927df0e3a27dee1f3bc01c5725f4ccefa36ba5f747e12a418",
    "fft16.vol00+1.par3": "7cdefb29a50f0e4b28a0ff26fd25e12a0b9733c7f900b0b3dc04cf84859572af",
    "fft16.vol01+2.par3": "7c465a36eb50de313bf47e473180a00395f37b683024f6a16ecb6f49de9e9364",
    "fft16.vol03+4.par3": "b9fef35ad7a7a39a733ccaa58e88a1c74d59c9a3bb658583951e2973b6b30308",
    "fft16.vol07+8.par3": "37ae162486f2d73d46aa0f4086ab9fa3a32970b332586c5dff14f577e211b0f2",
    "fft16.vol15+1.par3": "2f18b81f790f715f080938c3c26c8912d1668ed55ce0b111823e4d50886abf1e",
    "interleaved.par3": "be8649171973b0d27ccf39f5721196f25667c8194c4966863f98b856b280df81",
    "interleaved.vol0+1.par3": "54e77c9ffd4256159b1864b7f9ebb04ef4b06030ac5a321c31a5681cab6f7932",
    "interleaved.vol1+2.par3": "f08d7d62e2e551628c9caae5f040ead9beb3165992ccf15cce037d40560ec1e7"
  },
  "additional_commands": [
    [
      "par3",
      "c",
      "-s64",
      "-e8",
      "-c16",
      "-cm64",
      "fft16.par3",
      "input.bin"
    ],
    [
      "par3",
      "c",
      "-s1024",
      "-e8",
      "-i2",
      "-c9",
      "-cm24",
      "interleaved.par3",
      "input.bin"
    ]
  ]
}
```

## Initial container generation record

```json
{
  "reference_commit": "2971702e501f1350b1c7b9d11369af9157d6ed56",
  "commands": [
    "par3 i inside.zip",
    "par3 i inside.7z",
    "par3 i inside64.zip"
  ],
  "archive_recipes": {
    "inside.zip": "Python zipfile ZIP_DEFLATED input.bin: bytes((i*73+i//29)%256 for i in range(14000)); original retained before insertion",
    "inside.7z": "7zz 26.01 a -t7z -mx=1 -mtc=off -mta=off -mtm=off inside.7z input.bin; same input recipe",
    "inside64.zip": "Python zipfile ZIP_STORED, 65536 empty members named str(i). Before PAR3 insertion only, set ZIP EOCD central-directory size and offset to valid ZIP64 0xffffffff sentinels; the ZIP64 record retains real values."
  },
  "notes": "All inserted PAR3 bytes are unmodified official output. Original archives are retained as paired inputs. ZIP64 sentinel normalization addresses the pinned reference detector rejecting count-only ZIP64; no PAR3 packets existed at normalization time.",
  "sha256": {
    "inside-original.zip": "a7e6fe0bb60fc960171b207789971c1b88783728c6e9688ecb28801fd8658fd0",
    "inside.zip": "2cb759eb76fd5944f85677956c7c45ea08c2a8590b2346491dbf6b1a5f9c8ef8",
    "inside-original.7z": "790de9fe642157589a5f61f51772795e2343e2713a00773dd92dec348475bad7",
    "inside.7z": "7a745a680d9920615a72d94d6b7b46edf8b52a85cdc9b133ce11fdfedb6e2f13",
    "inside64-original.zip": "15a58f3a5f5a60de6042cd762aece3514d0db8871b649088e66a180df8091b11",
    "inside64.zip": "73d7278f203e3399a16b4157da5ecbb9b429d6fbacec4607e8c0d4908f115b9d"
  }
}
```
