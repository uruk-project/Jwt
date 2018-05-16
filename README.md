JSON Web Token  for .Net
===========

Provides support for JWT. 
This library aims to propose performant JWT primitives. 

## Versions
Current version - 0.1.0

## Usage
### JWT validation
``
	var key = SymmetricJwk.FromByteArray("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU");
    var reader = new JsonWebTokenReader(key);
	var validationParameters = new TokenValidationParameters
	{
	  ValidateAudience = true,
	  ValidAudience = "636C69656E745F6964",
	  ValidateIssuer = true
	};
	var result = _reader.TryReadToken("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI3NTZFNjk3MTc1NjUyMDY5NjQ2NTZFNzQ2OTY2Njk2NTcyIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20vIiwiaWF0IjoxNTA4MTg0ODQ1LCJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJleHAiOjE2MjgxODQ4NDV9.2U33urP5-MPw1ipbwEP4nqvEqlZiyUG9Hxi8YS_RQVk");
	if (result.Success)
	{
		Console.WriteLine("The token is " + result.Token);
	}
	else
	{
		Console.WriteLine("Failed to read the token. Reason: " + result.Status);
	}
``

### JWT creation
``
    var writer = new JsonWebTokenWriter();

	var expires = new DateTime(2033, 5, 18, 5, 33, 20, DateTimeKind.Utc);
	var issuedAt = new DateTime(2017, 7, 14, 4, 40, 0, DateTimeKind.Utc);
	var issuer = "https://idp.example.com/";
	var audience = "636C69656E745F6964";
	var descriptor = new JsonWebTokenDescriptor()
	{
		IssuedAt = issuedAt,
		Expires = expires,
		Issuer = issuer,
		Audience = audience,
		SigningKey = SharedKey
	};

	var token = writer.WriteToken(descriptor);
``
##Benchmark
TODO
