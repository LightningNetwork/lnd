### aez - AEZ (Duh)
#### Yawning Angel (yawning at schwanenlied dot me)

This is an implementation of [AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/),
primarily based on the reference code.  It appears to be correct and the
output matches [test vectors](https://github.com/nmathewson/aez_test_vectors).

Features:

 * Constant time, always.
 * Will use AES-NI if available on AMD64.
 * Unlike the `aesni` code, supports a vector of AD, nbytes > 16, and tau > 16.

Benchmarks:

| Version       | Message Size | ns/op    | MB/s    |
| ------------- | :----------: | -------: | ------: |
| aesni         | 1            | 2430     | 0.41    |
|               | 32           | 2161     | 14.80   |
|               | 512          | 2491     | 205.51  |
|               | 1024         | 2608     | 392.52  |
|               | 2048         | 2922     | 700.74  |
|               | 4096         | 3669     | 1116.12 |
|               | 8192         | 5096     | 1607.43 |
|               | 16384        | 7892     | 2075.93 |
|               | 32768        | 13214    | 2479.65 |
|               | 65536        | 24416    | 2684.11 |
|               | 1024768      | 381778   | 2684.20 |
|               |              |          |         |
| ct64 (no-asm) | 1            | 7185     | 0.14    |
|               | 32           | 9081     | 3.52    |
|               | 512          | 26117    | 19.60   |
|               | 1024         | 40259    | 25.43   |
|               | 2048         | 67867    | 30.18   |
|               | 4096         | 124411   | 32.92   |
|               | 8192         | 241456   | 33.93   |
|               | 16394        | 462033   | 35.46   |
|               | 32768        | 914127   | 35.85   |
|               | 65536        | 1804397  | 36.32   |
|               | 1024768      | 27380841 | 37.43   |
|               |              |          |         |
| ct32 (no-asm) | 1            | 6482     | 0.15    |
|               | 32           | 8673     | 3.69    |
|               | 512          | 26926    | 19.01   |
|               | 1024         | 45842    | 22.34   |
|               | 2048         | 83350    | 24.57   |
|               | 4096         | 159436   | 25.69   |
|               | 8192         | 322488   | 25.40   |
|               | 16394        | 618034   | 26.51   |
|               | 32768        | 1200462  | 27.30   |
|               | 65536        | 2366829  | 27.69   |
|               | 1024768      | 37128937 | 27.60   |

All numbers taken on an Intel i7-5600U with Turbo Boost disabled, running on
linux/amd64.  A 16 byte authenticator (tau) and no AD was used for each test.
Even on systems without AES-NI certain operations are done using SSE2
(eg: XORs), but for the purposes of benchmarking this was disabled for the
`ct64`/`ct32` tests.
