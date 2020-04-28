module Tests

open System
open Xunit
open JsonWebToken

[<Fact>]
let ``Issue #421`` () =
   use key = new SymmetricJwk("R9MyWaEoyiMYViVWo8Fk4TUGWiSoaW6U1nOqXri8_XU", SignatureAlgorithm.HmacSha256)
   let currentApp = "my app"    
   let descriptor =
       JwsDescriptor(
           KeyId = key.ToString(),
           JwtId = Guid.NewGuid().ToString(),
           IssuedAt = (DateTime.UtcNow |> Nullable),
           ExpirationTime = (DateTime.UtcNow.AddMinutes(30.0) |> Nullable),
           Issuer = (currentApp),
           Audience = (currentApp )
       )
   
   let writer = JwtWriter()
   let mutable exceptionRaised = false
   try  
      writer.WriteTokenString(descriptor) |> ignore
   with
        :? JwtDescriptorException as ex -> exceptionRaised <- true; 
 
   Assert.True(exceptionRaised)
