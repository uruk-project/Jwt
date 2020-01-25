using System;
using System.Collections.Generic;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.Tokens;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateInvalidToken : ValidateToken
    {
        private static byte[] signingKey = Tokens.SigningKey.ToArray();

        [GlobalSetup]
        public void Setup()
        {
            Jwt(new BenchmarkToken("JWS-0"));
            Wilson(new BenchmarkToken("JWS-0"));
            WilsonJwt(new BenchmarkToken("JWS-0"));
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override TokenValidationResult Jwt(BenchmarkToken token)
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
            catch (SecurityTokenEncryptionKeyNotFoundException e) { return null; }
            catch (SecurityTokenDecryptionFailedException e) { return null; }
            catch (SecurityTokenExpiredException e) { return null; }
            catch (SecurityTokenInvalidAudienceException e) { return null; }
            catch (SecurityTokenInvalidLifetimeException e) { return null; }
            catch (SecurityTokenInvalidSignatureException e) { return null; }
            catch (SecurityTokenNoExpirationException e) { return null; }
            catch (SecurityTokenNotYetValidException e) { return null; }
            catch (SecurityTokenReplayAddFailedException e) { return null; }
            catch (SecurityTokenReplayDetectedException e) { return null; }
            catch (SecurityTokenException e) { return null; }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Microsoft.IdentityModel.JsonWebTokens.TokenValidationResult WilsonJwt(BenchmarkToken token)
        {
            return WilsonJwtCore(token.InvalidTokenString, wilsonParameters);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override Dictionary<string, object> JoseDotNet(BenchmarkToken token)
        {
            try
            {
                return JoseDotNetCore(token.InvalidTokenString, Jose.JwsAlgorithm.HS256, signingKey);
            }
            catch (Exception e)
            {
                return null;
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetTokenValues))]
        public override IDictionary<string, object> JwtDotNet(BenchmarkToken token)
        {
            try
            {
                return JwtDotNetCore(token.InvalidTokenString, signingKey, true);
            }
            catch (Exception e)
            {
                return null;
            }
        }

        public override IEnumerable<string> GetTokens()
        {
            for (int i = 0; i < 10; i++)
            {
                yield return "JWS-" + i;
            }
        }
    }
}
