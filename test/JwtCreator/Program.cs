using JsonWebToken;
using Newtonsoft.Json.Linq;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;

namespace JwtCreator
{
    class Program
    {
        static void Main(string[] args)
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            var location = typeof(Program).GetTypeInfo().Assembly.Location;
            var dirPath = Path.GetDirectoryName(location);
            var keysPath = Path.Combine(dirPath, "./jwks.json"); ;
            var jwksString = File.ReadAllText(keysPath);
            var jwks = new JsonWebKeySet(jwksString);

            var descriptorsPath = Path.Combine(dirPath, "./descriptors.json");
            var descriptorsString = File.ReadAllText(descriptorsPath);
            var descriptors = JArray.Parse(descriptorsString).Select(t => new JsonWebTokenDescriptor(t.ToString()));

            var handler = new JwtSecurityTokenHandler();
            var result = new JArray();
            var descriptor = descriptors.First();
            foreach (var key in jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Sig))
            {
                var payload = new System.IdentityModel.Tokens.Jwt.JwtPayload();
                var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.JsonWebKey(key.ToString()), key.Alg);
                var header = new System.IdentityModel.Tokens.Jwt.JwtHeader(signingCredentials);
                header.Remove("typ");
                foreach (var claim in descriptor.Payload)
                {
                    payload.Add(claim.Key, claim.Value);
                }

                var token = new JwtSecurityToken(header, payload);
                var jwt = handler.WriteToken(token);
                result.Add(jwt);
            }

            var encryptionAlgorithms = new[] { SecurityAlgorithms.Aes128CbcHmacSha256, SecurityAlgorithms.Aes192CbcHmacSha384, SecurityAlgorithms.Aes256CbcHmacSha512 };
            foreach (var key in jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Enc))
            {
                foreach (var enc in encryptionAlgorithms)
                {
                    var payload = new System.IdentityModel.Tokens.Jwt.JwtPayload();
                    var signingKey = jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
                    var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(new Microsoft.IdentityModel.Tokens.JsonWebKey(signingKey.ToString()), signingKey.Alg);
                    var header = new System.IdentityModel.Tokens.Jwt.JwtHeader(signingCredentials);
                    header.Remove("typ");
                    var token = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor();
                    token.SigningCredentials = signingCredentials;
                    var encryptionCredentials = new Microsoft.IdentityModel.Tokens.EncryptingCredentials(new Microsoft.IdentityModel.Tokens.JsonWebKey(key.ToString()), key.Alg, enc);
                    token.EncryptingCredentials = encryptionCredentials;
                    token.Subject = new ClaimsIdentity();
                    foreach (var claim in descriptor.Payload)
                    {
                        token.Subject.AddClaim(new Claim(claim.Key, claim.Value.ToString()));
                    }

                    token.Expires = DateTime.UtcNow.AddYears(10);
                    var jwt = handler.CreateEncodedJwt(token);
                    result.Add(jwt);
                }
            }


            var jwsPath = Path.Combine(dirPath, "./jwts.json");
            File.WriteAllText(jwsPath, result.ToString());
        }
    }
}