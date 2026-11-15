# QR fixtures: where they come from

`vectors.json` holds 25 module matrices (`rows`: strings of `1` dark / `0` light, no quiet zone) for byte mode, ECC level M,
with the input `text` (encoded as UTF-8) and the `version`. They were recorded ONCE by `record.py` from an encoder that is
not part of this repository:

- Encoder: **libqrencode 4.1.1** (`qrencode -t ASCII -m 0 -l M -8`, automatic mask choice).
- Every recorded code was also rendered to a PNG by that encoder and decoded back to the exact input bytes by two independent
  decoders: **zbar 0.23.93** (`zbarimg --raw --set binary`) and **ZXing-C++ 3.1.1** (`ZXingReader`, which also reported the
  same version and ECC level M).
- Cases: the setup URL (43 bytes) and the recover URL (45 bytes) of a 24-byte host, a 100-byte setup URL, a UTF-8 input, one
  byte, and for every version 1 to 10 the shortest and the longest input that selects it (14, 26, 42, 62, 84, 106, 122, 152,
  180 and 213 bytes are the byte capacities at level M).

`src/pure/qr.ts` is never used to produce or check a fixture. To change a fixture, rerun `record.py`, name the new tool
versions here, and say why in the commit.
