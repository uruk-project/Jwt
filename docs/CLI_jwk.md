# dotnet-jwk

`dotnet-jwk` is a JSON Web Key manager for `dotnet`.
It allow to generate, encrypt, decrypt, convert and check JWK.

You can:
 - Creates symmetric JWK for AES or HMAC algorithms (`kty='oct'`)
 - Creates asymmetric JWK for RSA algorithms (`kty='RSA'`)
 - Creates symmetric JWK for elliptical curve algorithms (`kty='EC'`)
 - Encrypts JWK with `PBES2`
 - Decrypts JWK with `PBES2`
 - Converts a `PEM` key file into JWK
 - Converts a `X509` certificate file into JWK
 - Checks the validity of a JWK

# How To Install
The `dotnet-jwk` nuget package is [published to nuget.org](https://www.nuget.org/packages/dotnet-jwk/).

You can install the tool using the following command.
```
dotnet tool install -g dotnet-jwk
```

# How To Use

## Symmetric JWK generation
Creates a new JWK of type 'oct'

```
Usage:
  dotnet-jwk new oct [options]

Options:
  -l, --length <length> (REQUIRED)                                                    Length in bits of the key. Must be between 0 and 512.
  -o, --output-path <output-path>                                                     The shared key output path.
  -p, --password <password>                                                           The password for the key encryption.
  --iteration-count <iteration-count>                                                 The iteration count used for the password derivation.
  --salt-size <salt-size>                                                             The salt size in bytes used for the password derivation.
  --alg <A128GCMKW|A128KW|A192GCMKW|A192KW|A256GCMKW|A256KW|dir|HS256|HS384|HS512>    The algorithm intended for use with the key. Supported algorithms are HS256, HS384,
                                                                                      HS512, A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW, dir
  --use <enc|sig>                                                                     The public key intended use (sig, enc).
  --key-ops <deriveBits|encrypt|sign|unwrapKey|verify|wrapKey>                        The operation for which the key is intended to be used (sign, verify, encrypt,
                                                                                      encrypt, wrapKey, unwrapKey, deriveBits).
  --kid <kid>                                                                         The key identifier.
  --no-kid                                                                            Does not auto-generate a key identifier.
  --force                                                                             Erase the output file whether it exist.
  -v, --verbose                                                                       Show verbose output.
  -?, -h, --help                                                                      Show help and usage information
```

The minimum key length is 8 bits. The maximum key length is 512 bits. 
The recommended or required key size per algorithm:

 Algorithm    | Key length  
--------------|-----------
A128KW        | 128 bits                               
A128GCM       | 128 bits
A128GCMKW     | 128 bits
A192GCM       | 192 bits
A192KW        | 192 bits                               
A192GCMKW     | 192 bits
HS256         | 256 bits                               
A256KW        | 256 bits                               
A256GCM       | 256 bits
A256GCMKW     | 256 bits
A128CBC-HS256 | 256 bits
HS384         | 384 bits                               
A192CBC-HS384 | 384 bits
HS512         | 512 bits  
A256CBC-HS512 | 512 bits


### Example
Example | Description
--|--
dotnet-jwk new oct -l 128 | Generates a new symmetric key of 128 bits
dotnet-jwk new oct -l 128 --alg HS256 | Generates a new symmetric key of 128 bits for `HS256` signature algorithm
dotnet-jwk new oct -l 128 --alg HS256 --use sig | Generates a new symmetric key of 128 bits for `HS256` signature algorithm
dotnet-jwk new oct -l 128 -p P@ssw0rd | Generates a new symmetric key of 128 bits, encrypted with PBES2
dotnet-jwk new oct -l 128 --no-kid | Generates a new symmetric key of 128 bits, without kid generation
dotnet-jwk new oct -l 128 -o ./jwk.json | Generates a new symmetric key of 128 bits, and writes it to the file `jwk.json`



## RSA JWK generation
Creates a new JWK of type 'RSA'

```
Usage:
  dotnet-jwk new RSA [options]

Options:
 -l, --length <length> (REQUIRED)                                                      Length in bits of the key. Must be between 0 and 16384.
  -o, --output-path <output-path>                                                       The private key output path.
  --public-output-path <public-output-path>                                             The public key output path.
  -p, --password <password>                                                             The password for the key encryption.
  --iteration-count <iteration-count>                                                   The iteration count used for the password derivation.
  --salt-size <salt-size>                                                               The salt size in bytes used for the password derivation.
  --alg                                                                                 The algorithm intended for use with the key. Supported algorithms are RS256,
  <PS256|PS384|PS512|RS256|RS384|RS512|RSA-OAEP|RSA-OAEP-256|RSA-OAEP-384|RSA-OAEP-5    RS384, RS512, PS256, PS384, PS512, RSA1_5, RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384,
  12|RSA1_5>                                                                            RSA-OAEP-512
  --use <enc|sig>                                                                       The public key intended use (sig, enc).
  --key-ops <deriveBits|encrypt|sign|unwrapKey|verify|wrapKey>                          The operation for which the key is intended to be used (sign, verify, encrypt,
                                                                                        encrypt, wrapKey, unwrapKey, deriveBits).
  --kid <kid>                                                                           The key identifier.
  --no-kid                                                                              Does not auto-generate a key identifier.
  --force                                                                               Erase the output file whether it exist.
  -v, --verbose                                                                         Show verbose output.
  -?, -h, --help                                                                        Show help and usage information
```
The minimum key length is 512 bits. The maximum key length is 16384 bits. 
The minimal key length for RSA algoritmh in for JWT is 2048 bits, 
but the current recommended minimal key length is 3072 bit.

Generating a RSA key of 16384 bits may takes minutes.


### Example
Example | Description
--|--
dotnet-jwk new RSA -l 3072 | Generates a new RSA key of 3072 bits
dotnet-jwk new RSA -l 3072 --alg PS256 | Generates a new RSA key of 3072 bits for `PS256` signature algorithm
dotnet-jwk new RSA -l 3072 --alg PS256 --use sig | Generates a new RSA key of 3072 bits for `PS256` signature algorithm
dotnet-jwk new RSA -l 3072 -p P@ssw0rd | Generates a new RSA key of 3072 bits, encrypted with PBES2
dotnet-jwk new RSA -l 3072 --no-kid | Generates a new RSA key of 3072 bits, without kid generation
dotnet-jwk new RSA -l 3072 -o ./jwk.json | Generates a new RSA key of 3072 bits, and writes it to the file `jwk.json`


## Elliptical curve JWK generation
Creates a new JWK of type 'EC'

```
Usage:
  dotnet-jwk new EC [options]

Options:
  -c, --curve <P-256|P-384|P-521|secp256k1> (REQUIRED)                              The elliptical curve name. Supported curves: P-256, P-384, P-521, secp256k1.
  -o, --output-path <output-path>                                                   The private key output path.
  --public-output-path <public-output-path>                                         The public key output path.
  -p, --password <password>                                                         The password for the key encryption.
  --iteration-count <iteration-count>                                               The iteration count used for the password derivation.
  --salt-size <salt-size>                                                           The salt size in bytes used for the password derivation.
  --alg <ECDH-ES|ECDH-ES+A128KW|ECDH-ES+A192KW|ECDH-ES+A256KW|ES256|ES384|ES512>    The algorithm intended for use with the key. Supported algorithms are ES256, ES384,
                                                                                    ES512, ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
  --use <enc|sig>                                                                   The public key intended use (sig, enc).
  --key-ops <deriveBits|encrypt|sign|unwrapKey|verify|wrapKey>                      The operation for which the key is intended to be used (sign, verify, encrypt,
                                                                                    encrypt, wrapKey, unwrapKey, deriveBits).
  --kid <kid>                                                                       The key identifier.
  --no-kid                                                                          Does not auto-generate a key identifier.
  --force                                                                           Erase the output file whether it exist.
  -v, --verbose                                                                     Show verbose output.
  -?, -h, --help                                                                    Show help and usage information                                        Show help and usage information
```

### Example
Example | Description
--|--
dotnet-jwk new EC -c P-256 | Generates a new elliptical curve key with P-256 curve
dotnet-jwk new EC -c P-256 --alg ES256 | Generates a new elliptical curve key with P-256 curve for `ES256` signature algorithm
dotnet-jwk new EC -c P-256 --alg ES256 --use sig | Generates a new elliptical curve key with P-256 curve for `ES256` signature algorithm
dotnet-jwk new EC -c P-256 -p P@ssw0rd | Generates a new elliptical curve key with P-256 curve, encrypted with PBES2
dotnet-jwk new EC -c P-256 --no-kid | Generates a new elliptical curve key with P-256 curve, without kid generation
dotnet-jwk new EC -c P-256 -o ./jwk.json | Generates a new elliptical curve key with P-256 curve, and writes it to the file `jwk.json`


## Encrypt a JWK
  Encrypts a JWK
```
Usage:
  dotnet-jwk encrypt [options]

Options:
  -k, --key <key>                         The key to encrypt
  -i, --input-path <input-path>           The plain key input path. Use this option when the key is stored into a file.
  -o, --output-path <output-path>         The private key output path.
  -p, --password <password> (REQUIRED)    The password for the key encryption.
  --iteration-count <iteration-count>     The iteration count used for the password derivation.
  --salt-size <salt-size>                 The salt size in bytes used for the password derivation.
  --force                                 Erase the output file whether it exist.
  -v, --verbose                           Show verbose output.
  -?, -h, --help                          Show help and usage information
```

The `-k` option must not be used with the option `-i`.

### Example
Example | Description
--|--
dotnet-jwk encrypt -k `"{""kty"":'"oct"",""k"":""FxjKToF2GpDacyDEP-LMHA""}"` -p P@ssw0rd | Encrypts the JWK with the password `P@ssw0rd`
dotnet-jwk encrypt -k `"{""kty"":'"oct"",""k"":""FxjKToF2GpDacyDEP-LMHA""}"` -p P@ssw0rd --iteration-count 100000 --salt-size 128 | Encrypts the JWK with the password `P@ssw0rd`, with 100000 iterations, and a salt of 128 bits
dotnet-jwk encrypt -k `"{""kty"":'"oct"",""k"":""FxjKToF2GpDacyDEP-LMHA""}"` -p P@ssw0rd -o encrypted.json | Encrypts the JWK with the password `P@ssw0rd` into the file `encrypted.json`
dotnet-jwk encrypt -i ./jwk.json -p P@ssw0rd | Encrypts the JWK located in the file `jwk.json` with the password `P@ssw0rd`

Please note the -k parameter require to be wrapped with quotes, and the existing quotes need to be doubled.

## Decrypt a JWK
Decrypts a JWK

```
Usage:
  dotnet-jwk decrypt [options]

Options:
  -k, --key <key>                         The key to encrypt
  -i, --input-path <input-path>           The plain key input path. Use this option when the key is stored into a file.
  -o, --output-path <output-path>         The private key output path.
  -p, --password <password> (REQUIRED)    The password for the key encryption.
  --iteration-count <iteration-count>     The iteration count used for the password derivation.
  --salt-size <salt-size>                 The salt size in bytes used for the password derivation.
  --force                                 Erase the output file whether it exist.
  -v, --verbose                           Show verbose output.
  -?, -h, --help                          Show help and usage information
```
The `-k` option must not be used with the option `-i`.

### Example
Example | Description
--|--
dotnet-jwk decrypt -k eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiMnd3U0ZpSFRvV0J1VzdNR180Q1UtTkY3cFVRcTFYd3ZiZUZwX01HdGdNVSIsInR5cCI6InBsYWluIiwicDJzIjoieW5aei1KeUh4QWMiLCJwMmMiOjEwMDB9.XGN9I2AfqwjOo2j_cYXKXcxGYTlEXArDXNPOsEV8MHG8wjs8-sSyYQ.ZD_10qOGWD_fT3Ank5bhiQ.9b5ddA4Dooc5hk0gtzeDjZMud7bFACfuYCzqwI9_9tVgMwxGM4uiy9ubWTcxhCHpS5Uirixh0sojTS-A9E402CBTTCXyh38xg3qMF-lpEi2PVkQ0GfOJ-o0CgyIAqToIjdm3LkDseVkZz_sM1LyMFA.ghH8Ily6BnkhtCPrDAf2uw -p P@ssw0rd | Decrypts the encrypted JWK with the password `P@ssw0rd`
dotnet-jwk decrypt -i ./encrypted.json -p P@ssw0rd | Encrypts the JWK located in the file `jwk.json` with the password `P@ssw0rd`
dotnet-jwk decrypt -k `"{""kty"":'"oct"",""k"":""FxjKToF2GpDacyDEP-LMHA""}"` -p P@ssw0rd --iteration-count 100000 --salt-size 128 | Encrypts the JWK with the password `P@ssw0rd`, with 100000 iterations, and a salt of 128 bits
dotnet-jwk decrypt -i ./encrypted.json -p P@ssw0rd -o ./decrypted.json | Encrypts the JWK located in the file `encrypted.json` with the password `P@ssw0rd`, and store it into the file `decrypted.json`


## Convert a PEM file to JWK
  Convert a PEM key file to JWK format
```
Usage:
  dotnet-jwk convert PEM [options]

Options:
  -i, --input-path <input-path> (REQUIRED)     The file key input path.
  -o, --output-path <output-path>              The private key output path.
  --public-output-path <public-output-path>    The public key output path.
  -p, --password <password>                    The password for the key encryption.
  --iteration-count <iteration-count>          The iteration count used for the password derivation.
  --salt-size <salt-size>                      The salt size in bytes used for the password derivation.
  --force                                      Erase the output file whether it exist.
  -v, --verbose                                Show verbose output.
  -?, -h, --help                               Show help and usage information
```


### Example
Example | Description
--|--
dotnet-jwk convert PEM -i ./key.pem -o ./jwk.json | Convert PEM located in the file `key.pem`, and store it into the file `jwk.json`


## Convert a X509 certificate file to JWK
  Convert a X509 file certificate to JWK format
```
Usage:
  dotnet-jwk convert X509 [options]

Options:
  -i, --input-path <input-path> (REQUIRED)         The file key input path.
  -o, --output-path <output-path>                  The private key output path.
  --public-output-path <public-output-path>        The public key output path.
  --certificate-password <certificate-password>    The password of the certificate.
  -p, --password <password>                        The password for the key encryption.
  --iteration-count <iteration-count>              The iteration count used for the password derivation.
  --salt-size <salt-size>                          The salt size in bytes used for the password derivation.
  --force                                          Erase the output file whether it exist.
  -v, --verbose                                    Show verbose output.
  -?, -h, --help                                   Show help and usage information
```

### Example
Example | Description
--|--
dotnet-jwk convert X509 -i ./certificate.der -o ./jwk.json | Convert X509 certificate located in the file `certificate.der`, and store it into the file `jwk.json`
dotnet-jwk convert X509 -i ./certificate.der --certificate-password P@ssw0rd -o ./jwk.json | Convert X509 certificate located in the file `certificate.der`, and store it into the file `jwk.json`

## Check the JWK validity
   Checks the validaty of a JWK
```
Usage:
  dotnet-jwk check [options]

Options:
  -i, --input-path <input-path> (REQUIRED)    The file key input path.
  -v, --verbose                               Show verbose output.
  -?, -h, --help                              Show help and usage information
```

### Example
Example | Description
--|--
dotnet-jwk check -i ./jwk.json | Checks whether JWK located in the file `jwk.json` is valid

## How To Uninstall
You can uninstall the tool using the following command.

```
dotnet tool uninstall -g dotnet-jwk
```
