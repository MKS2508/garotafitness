[7-Zip](https://github.com/ip7z/7zip) 26.02, commit `f9d78aff31a5f2521ae7ddbdc97c4a8855808959`.

These C files are the public-domain LZMA encoder used by the installer's
`7z.exe`. `reconstruct/sevenz` compiles them as a Guest. Do not mix them with
`lzma-sdk19`, which remains the encoder for `fgpack.exe`.
