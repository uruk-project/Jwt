# Performance considerations

## Signature algorithm choice
|  Algorithm | Verification |   Generation |
|----------- |-------------:|-------------:|
|   ES256    |   698.682 μs |   702.371 µs |
|  ES256X    |   762.874 μs |   787.558 µs |
|   ES384    | 1,430.796 μs | 1,354.048 µs |
|   ES512    | 2,898.478 μs | 2,750.035 µs |
|   HS256    |     4.094 μs |     3.538 µs |
|   HS384    |     3.923 μs |     3.401 µs |
|   HS512    |     3.937 μs |     3.393 µs |
|   PS256    |   143.842 μs | 5,486.229 µs |
|   PS384    |   144.762 μs | 5,547.751 µs |
|   PS512    |   142.725 μs | 5,726.623 µs |
|   RS256    |   134.399 μs | 5,472.436 µs |
|   RS384    |   139.938 μs | 5,582.477 µs |
|   RS512    |   137.010 μs | 5,620.581 µs |

### TD ; DR
Use HSXXX when the you do not require non-repudation.
Otherwise:
Use RSXXX/PSXXX when the performance is required on the recipient side.
Use ESXXX when the performance is required on the issuer side.


Hash algorithms has nearly no impact on the performance. The throughput of SHA2 algorithms are much higher that the associated signing algorithms.

Outside of any security consideration, HMAC SHA2 give the best performance, for signature generation as well for signature verification. 
This is a symmetric algorithm, and should be used only when the repudiation is not an issue (ie. the issuer is the recipient).

All RSA algorithms (RSXXX & PSXXX) are similaire in term of performance. 
RSA algorithms performs faster for verification that ECDSA algorithms, but it is the opposite 


## Encryption algorithm choice
TBC 

## Key exchange algorithm choice
TBC