### Read Encrypted JWT (A128CBC-HS256 & A128KW, with HS256 signed JWT)
| Method |      token |      Mean |     Op/s | Ratio | Allocated |
|------- |----------- |----------:|---------:|------:|----------:|
|    Jwt | JWE-medium |  36.16 us | 27,652.7 |  1.00 |   4.35 KB |
| Wilson | JWE-medium | 228.86 us |  4,369.5 |  6.41 |  65.39 KB |
|        |            |           |          |       |           |
|    Jwt |  JWE-small |  18.16 us | 55,055.5 |  1.00 |    2.2 KB |
| Wilson |  JWE-small | 138.53 us |  7,218.5 |  7.57 |  38.17 KB |


### Read Signed JWT (HS256)
| Method |      token |      Mean |      Op/s | Ratio | Allocated |
|------- |----------- |----------:|----------:|------:|----------:|
|    Jwt | JWS-medium | 18.074 us |  55,329.5 |  1.00 |   3.34 KB |
| Wilson | JWS-medium | 94.284 us |  10,606.3 |  5.32 |  32.54 KB |
|        |            |           |           |       |           |
|    Jwt |  JWS-small |  7.340 us | 136,248.7 |  1.00 |   1.19 KB |
| Wilson |  JWS-small | 44.804 us |  22,319.6 |  6.01 |  17.91 KB |


### Read unsigned JWT
| Method |    payload |     Mean |      Op/s | Ratio | Allocated |
|------- |----------- |---------:|----------:|------:|----------:|
|    Jwt | JWE-medium | 2.380 us | 420,160.2 |  1.00 |      69 B |
| Wilson | JWE-medium | 8.852 us | 112,968.3 |  3.75 |    2760 B |
|        |            |          |           |       |           |
|    Jwt |  JWE-small | 1.279 us | 782,159.6 |  1.00 |      69 B |
| Wilson |  JWE-small | 6.226 us | 160,625.7 |  4.89 |    1708 B |


### Write encrypted JWT (A128CBC-HS256 & A128KW, with HS256 signed JWT)
| Method |    payload |      Mean |     Op/s | Ratio | Allocated |
|------- |----------- |----------:|---------:|------:|----------:|
|    Jwt | JWE-medium |  47.06 us | 21,250.4 |  1.00 |   1.08 KB |
| Wilson | JWE-medium | 175.12 us |  5,710.4 |  3.75 |   43.3 KB |
|        |            |           |          |       |           |
|    Jwt |  JWE-small |  23.89 us | 41,862.2 |  1.00 |   1.08 KB |
| Wilson |  JWE-small | 127.75 us |  7,827.6 |  5.28 |  26.72 KB |


### Write signed JWT (HS256)
| Method |    payload |      Mean |      Op/s | Ratio | Allocated |
|------- |----------- |----------:|----------:|------:|----------:|
|    Jwt | JWS-medium | 16.328 us |  61,245.9 |  1.00 |     184 B |
| Wilson | JWS-medium | 43.174 us |  23,162.1 |  2.70 |   17520 B |
|        |            |           |           |       |           |
|    Jwt |  JWS-small |  7.187 us | 139,135.6 |  1.00 |     184 B |
| Wilson |  JWS-small | 18.688 us |  53,510.4 |  2.61 |    7768 B |


### Write unsigned JWT
| Method |    payload |      Mean |      Op/s | Ratio | Allocated |
|------- |----------- |----------:|----------:|------:|----------:|
|    Jwt | JWT-medium |  7.812 us | 128,009.4 |  1.00 |     184 B |
| Wilson | JWT-medium | 27.077 us |  36,932.1 |  3.46 |   14008 B |
|        |            |           |           |       |           |
|    Jwt |  JWT-small |  2.642 us | 378,517.2 |  1.00 |     184 B |
| Wilson |  JWT-small | 10.265 us |  97,418.9 |  3.89 |    6056 B |



Small token: Token with 6 claims
Medium token: Token with 22 claims

Wilson was tested in version 5.3.0.
