### Read & validate signed JWT (HS256)
![JWS validation, operation per second. Higher is better.](docs/validate_jws_ops.png)

*JWS validation, operation per second. Higher is better.*
![JWS validation, allocated bytes per operation. Lower is better.](docs/validate_jws_allocated.png)

*JWS validation, allocated bytes per operation. Lower is better.*

### Read & validate encrypted JWT (A128CBC-HS256 & A128KW, with HS256 signed JWT)
![JWE validation, operation per second. Higher is better.](docs/validate_jwe_ops.png)

*JWE validation, operation per second. Higher is better.*
![JWE validation, allocated bytes per operation. Lower is better.](docs/validate_jwe_allocated.png)

*JWE validation, allocated bytes per operation. Lower is better.*

### Write signed JWT (HS256)
![JWS creation, operation per second. Higher is better.](docs/write_jws_ops.png)

*JWS creation, operation per second. Higher is better.*
![JWS creation, allocated bytes per operation. Lower is better.](docs/write_jws_allocated.png)

*JWS creation, allocated bytes per operation. Lower is better.*
### Write encrypted JWT (A128CBC-HS256 & A128KW, with HS256 signed JWT)
![JWE creation, operation per second. Higher is better.](docs/write_jwe_ops.png)

*JWE creation, operation per second. Higher is better.*
![JWE creation, allocated bytes per operation. Lower is better.](docs/write_jwe_allocated.png)

*JWE creation, allocated bytes per operation. Lower is better.*

Tokens used in the benchmarks have from 6 to 96 claims.

JsonWebToken was tested in version 1.0.0.
https://www.nuget.org/packages/JsonWebToken/5.6.0

Wilson was tested in version 5.6.0.
https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/5.6.0

Wilson JWT was tested in version 5.6.0.
https://www.nuget.org/packages/Microsoft.IdentityModel.JsonWebTokens/5.6.0

Jwt.Net was tested in version 5.3.1.
https://www.nuget.org/packages/JWT/5.3.1

jose-jwt was tested in version 2.5.0.
https://www.nuget.org/packages/jose-jwt/2.5.0
