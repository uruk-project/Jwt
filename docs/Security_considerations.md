# Security considerations

## Key length equivalent
|  RSA key length (bits) | ECC key length (bits) | 
|-----------------------:|----------------------:|
| 3072                   | 256                   | 
| 7680                   | 384                   | 
| 15360                  | 521                   |  

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

## Key exchange algorithm choice
