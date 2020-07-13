using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.Tokens;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    public class ValidateInvalidToken : ValidateToken
    {
        private static readonly byte[] SigningKey = Tokens.SigningKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            var token = GetTokenValues().First();
            JsonWebToken(token);
            Wilson(token);
            WilsonJwt(token);
            jose_jwt(token);
            Jwt_Net(token);
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override TokenValidationResult JsonWebToken(BenchmarkToken token)
        {
            return JwtCore(token.InvalidTokenBinary, tokenValidationPolicy);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override ClaimsPrincipal Wilson(BenchmarkToken token)
        {
            try
            {
                return WilsonCore(token.InvalidTokenString, wilsonParameters);
            }
            catch (SecurityTokenEncryptionKeyNotFoundException) { return null!; }
            catch (SecurityTokenDecryptionFailedException) { return null!; }
            catch (SecurityTokenExpiredException) { return null!; }
            catch (SecurityTokenInvalidAudienceException) { return null!; }
            catch (SecurityTokenInvalidLifetimeException) { return null!; }
            catch (SecurityTokenInvalidSignatureException) { return null!; }
            catch (SecurityTokenNoExpirationException) { return null!; }
            catch (SecurityTokenNotYetValidException) { return null!; }
            catch (SecurityTokenReplayAddFailedException) { return null!; }
            catch (SecurityTokenReplayDetectedException) { return null!; }
            catch (SecurityTokenException) { return null!; }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Microsoft.IdentityModel.Tokens.TokenValidationResult WilsonJwt(BenchmarkToken token)
        {
            return WilsonJwtCore(token.InvalidTokenString, wilsonParameters);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Dictionary<string, object> jose_jwt(BenchmarkToken token)
        {
            try
            {
                return JoseDotNetCore(token.InvalidTokenString, Jose.JwsAlgorithm.HS256, SigningKey);
            }
            catch (Exception)
            {
                return null!;
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override IDictionary<string, object> Jwt_Net(BenchmarkToken token)
        {
            try
            {
                return JwtDotNetCore(token.InvalidTokenString, SigningKey, true);
            }
            catch (Exception)
            {
                return null!;
            }
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWS " + (i == 0 ? "" : i.ToString()) + "6 claims";
            }
        }
    }
}
