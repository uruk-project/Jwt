using System;
using System.Buffers;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Xunit;
using System.Linq;
using System.Runtime.CompilerServices;

namespace JsonWebToken.Tests
{
    public class JwtDocumentTests : IClassFixture<KeyFixture>, IClassFixture<TokenFixture>
    {
        private readonly KeyFixture _keys;
        private readonly TokenFixture _tokens;

        public JwtDocumentTests(KeyFixture keys, TokenFixture tokens)
        {
            _keys = keys;
            _tokens = tokens;
        }

        private class TokenSegment<T> : ReadOnlySequenceSegment<T>
        {
            public TokenSegment(ReadOnlyMemory<T> memory) => Memory = memory;

            public TokenSegment<T> Add(ReadOnlyMemory<T> mem)
            {
                var segment = new TokenSegment<T>(mem)
                {
                    RunningIndex = RunningIndex + Memory.Length
                };
                Next = segment;
                return segment;
            }
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_ValidMultipleSequence(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(jwt);

            TokenSegment<byte> firstSegment = new TokenSegment<byte>(utf8Jwt.AsMemory(0, 10));
            var secondSegment = firstSegment.Add(utf8Jwt.AsMemory(10, 10));
            var thirdSegment = secondSegment.Add(utf8Jwt.AsMemory(20));
            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(firstSegment, 0, thirdSegment, thirdSegment.Memory.Length);

            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument_Reference.TryParse(sequence, builder, out var document);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_ValidSingleSequence(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(jwt);

            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(utf8Jwt);

            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument_Reference.TryParse(sequence, builder, out var document);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_Valid(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument_Reference.TryParse(jwt, builder, out var document);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(InvalidTokenTestData))]
        public void ReadJwt_Invalid(string jwt, TokenValidationStatus expectedStatus)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature(_keys.SigningKey)
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks)
                    .Build();

            var result = JwtDocument_Reference.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(expectedStatus, document.Error.Status);
        }

        [Fact]
        public void ReadJwt_HttpKeyProvider_Valid()
        {
            var httpHandler = new TestHttpMessageHandler
            {
                Sender = BackchannelRequestToken
            };
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature("https://demo.identityserver.io/.well-known/openid-configuration/jwks", handler: httpHandler)
                    .Build();

            var jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1Mjc5NzMyNDIsImV4cCI6MTUyNzk3Njg0MiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19.PFI6Fl8J6nlk3MyDwUemy6e4GjtyNoDabuQcUdOoQRGUjVAhv0UKqSOujg4Y_g23nPCGGMNOVNDiyK9StV4NdUrPemdShR6gykKd-FE1n7uHEwN6vsTDV_EeoF5ZdQsqEVo8zxfWoCIVP2Llj7TTwaoNpnhl9fkHvCc75XqYyF7SkiQAXGGGTExNh12kEI_Hb_rZvjJN2HCw1BsMx9-KFM69oFhT8ClAXeG3j3YsQ9ffjoZXV31S2Llzk-5Mf6BrR5CpCUHWWbfnEU21ko2NH7Y_aBJOwVAxyadj-89RR3-Ixpz3mUDxsZ4nmhLJDbrM9e1SRUq-oPmljIp53j-NXg";
            var result = JwtDocument_Reference.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1Mjc5NzMyNDIsImV4cCI6MTUyNzk3Njg0MiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19")]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0")]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.")]
        [InlineData("....")]
        [InlineData("...")]
        [InlineData("..")]
        [InlineData(".")]
        [InlineData("")]
        public void ReadJwt_Malformed(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .Build();

            var result = JwtDocument_Reference.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(TokenValidationStatus.MalformedToken, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl0sInVuZGVmaW5lZCI6IHRydWV9.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl0sInVuZGVmaW5lZCI6IHRydWV9.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl19.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl19.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiaW52YWxpZCJdLCJpbnZhbGlkIjogdHJ1ZX0.RkFJTA.", TokenValidationStatus.InvalidHeader, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiaW52YWxpZCJdLCJpbnZhbGlkIjogdHJ1ZX0.RkFJTA.", TokenValidationStatus.InvalidHeader, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.RkFJTA.", TokenValidationStatus.MalformedToken, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.RkFJTA.", TokenValidationStatus.MalformedToken, false)]
        public void ReadJwt_CriticalHeader_Invalid(string jwt, TokenValidationStatus expected, bool headerCacheEnabled)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false));
            if (!headerCacheEnabled)
            {
                policy.DisabledHeaderCache();
            }

            var result = JwtDocument_Reference.TryParse(jwt, policy.Build(), out var document);
            Assert.False(result);
            Assert.Equal(expected, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", true)]
        public void ReadJwt_CriticalHeader_Valid(string jwt, bool headerCacheEnabled)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false));
            if (!headerCacheEnabled)
            {
                policy.DisabledHeaderCache();
            }

            var result = JwtDocument_Reference.TryParse(jwt, policy.Build(), out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDB9.")]
        public void Issue489_Valid(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .EnableLifetimeValidation()
                .Build();

            var result = JwtDocument_Reference.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjE1MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.", TokenValidationStatus.Expired)]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6OTkwMDAwMDAwMH0.", TokenValidationStatus.NotYetValid)]
        [InlineData("eyJhbGciOiJub25lIn0.eyJuYmYiOjk5MDAwMDAwMDB9.", TokenValidationStatus.MissingClaim)]
        [InlineData("eyJhbGciOiJub25lIn0.e30.", TokenValidationStatus.MissingClaim)]
        public void Issue489_Invalid(string jwt, TokenValidationStatus status)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .EnableLifetimeValidation()
                .Build();

            var result = JwtDocument_Reference.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(status, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjE1MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6OTkwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJuYmYiOjk5MDAwMDAwMDB9.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDB9.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.e30.")]
        public void Issue489_NoValidation_Valid(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .Build();

            var result = JwtDocument_Reference.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        private HttpResponseMessage BackchannelRequestToken(HttpRequestMessage req)
        {
            if (req.RequestUri.AbsoluteUri == "https://demo.identityserver.io/.well-known/openid-configuration/jwks")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"6bbdca780af3a67163ca7531545da7a9\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                            Encoding.UTF8,
                            "application/json")
                };
            }
            throw new NotImplementedException(req.RequestUri.AbsoluteUri);
        }
    }

    public class JwtDocument2Tests : IClassFixture<KeyFixture>, IClassFixture<TokenFixture>
    {
        private readonly KeyFixture _keys;
        private readonly TokenFixture _tokens;

        public JwtDocument2Tests(KeyFixture keys, TokenFixture tokens)
        {
            _keys = keys;
            _tokens = tokens;
        }

        private class TokenSegment<T> : ReadOnlySequenceSegment<T>
        {
            public TokenSegment(ReadOnlyMemory<T> memory) => Memory = memory;

            public TokenSegment<T> Add(ReadOnlyMemory<T> mem)
            {
                var segment = new TokenSegment<T>(mem)
                {
                    RunningIndex = RunningIndex + Memory.Length
                };
                Next = segment;
                return segment;
            }
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_ValidMultipleSequence(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(jwt);

            TokenSegment<byte> firstSegment = new TokenSegment<byte>(utf8Jwt.AsMemory(0, 10));
            var secondSegment = firstSegment.Add(utf8Jwt.AsMemory(10, 10));
            var thirdSegment = secondSegment.Add(utf8Jwt.AsMemory(20));
            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(firstSegment, 0, thirdSegment, thirdSegment.Memory.Length);

            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument2.TryParse(sequence, builder, out var document);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_ValidSingleSequence(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(jwt);

            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(utf8Jwt);

            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument2.TryParse(sequence, builder, out var document);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_Valid(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument2.TryParse(jwt, builder, out var document);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(InvalidTokenTestData))]
        public void ReadJwt_Invalid(string jwt, TokenValidationStatus expectedStatus)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature(_keys.SigningKey)
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks)
                    .Build();

            var result = JwtDocument2.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(expectedStatus, document.Error.Status);
        }

        [Fact]
        public void ReadJwt_HttpKeyProvider_Valid()
        {
            var httpHandler = new TestHttpMessageHandler
            {
                Sender = BackchannelRequestToken
            };
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature("https://demo.identityserver.io/.well-known/openid-configuration/jwks", handler: httpHandler)
                    .Build();

            var jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1Mjc5NzMyNDIsImV4cCI6MTUyNzk3Njg0MiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19.PFI6Fl8J6nlk3MyDwUemy6e4GjtyNoDabuQcUdOoQRGUjVAhv0UKqSOujg4Y_g23nPCGGMNOVNDiyK9StV4NdUrPemdShR6gykKd-FE1n7uHEwN6vsTDV_EeoF5ZdQsqEVo8zxfWoCIVP2Llj7TTwaoNpnhl9fkHvCc75XqYyF7SkiQAXGGGTExNh12kEI_Hb_rZvjJN2HCw1BsMx9-KFM69oFhT8ClAXeG3j3YsQ9ffjoZXV31S2Llzk-5Mf6BrR5CpCUHWWbfnEU21ko2NH7Y_aBJOwVAxyadj-89RR3-Ixpz3mUDxsZ4nmhLJDbrM9e1SRUq-oPmljIp53j-NXg";
            var result = JwtDocument2.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1Mjc5NzMyNDIsImV4cCI6MTUyNzk3Njg0MiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19")]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0")]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.")]
        [InlineData("....")]
        [InlineData("...")]
        [InlineData("..")]
        [InlineData(".")]
        [InlineData("")]
        public void ReadJwt_Malformed(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .Build();

            var result = JwtDocument2.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(TokenValidationStatus.MalformedToken, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl0sInVuZGVmaW5lZCI6IHRydWV9.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl0sInVuZGVmaW5lZCI6IHRydWV9.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl19.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl19.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiaW52YWxpZCJdLCJpbnZhbGlkIjogdHJ1ZX0.RkFJTA.", TokenValidationStatus.InvalidHeader, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiaW52YWxpZCJdLCJpbnZhbGlkIjogdHJ1ZX0.RkFJTA.", TokenValidationStatus.InvalidHeader, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.RkFJTA.", TokenValidationStatus.MalformedToken, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.RkFJTA.", TokenValidationStatus.MalformedToken, false)]
        public void ReadJwt_CriticalHeader_Invalid(string jwt, TokenValidationStatus expected, bool headerCacheEnabled)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false));
            if (!headerCacheEnabled)
            {
                policy.DisabledHeaderCache();
            }

            var result = JwtDocument2.TryParse(jwt, policy.Build(), out var document);
            Assert.False(result);
            Assert.Equal(expected, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", true)]
        public void ReadJwt_CriticalHeader_Valid(string jwt, bool headerCacheEnabled)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false));
            if (!headerCacheEnabled)
            {
                policy.DisabledHeaderCache();
            }

            var result = JwtDocument2.TryParse(jwt, policy.Build(), out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDB9.")]
        public void Issue489_Valid(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .EnableLifetimeValidation()
                .Build();

            var result = JwtDocument2.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjE1MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.", TokenValidationStatus.Expired)]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6OTkwMDAwMDAwMH0.", TokenValidationStatus.NotYetValid)]
        [InlineData("eyJhbGciOiJub25lIn0.eyJuYmYiOjk5MDAwMDAwMDB9.", TokenValidationStatus.MissingClaim)]
        [InlineData("eyJhbGciOiJub25lIn0.e30.", TokenValidationStatus.MissingClaim)]
        public void Issue489_Invalid(string jwt, TokenValidationStatus status)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .EnableLifetimeValidation()
                .Build();

            var result = JwtDocument2.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(status, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjE1MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6OTkwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJuYmYiOjk5MDAwMDAwMDB9.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDB9.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.e30.")]
        public void Issue489_NoValidation_Valid(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .Build();

            var result = JwtDocument2.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        //[Fact]
        //public void Parse()
        //{
        //    //var json = Encoding.UTF8.GetBytes("{\"string\":\"hello\",\"number\":1234,\"boolean\":true,\"object\":{\"value\":1},\"array\":[1,2,3,4],\"null\":null}");
        //    var json = Encoding.UTF8.GetBytes("{\"string\":\"hello\",\"number\":1234,\"boolean\":true,\"object\":{\"value\":1},\"null\":null}");

        //    var result = JwtPayloadDocument.Parse(json);
        //    var elt = result.RootElement;
        //    Assert.Equal("hello", elt.GetProperty("string").GetString());
        //    Assert.Equal(1234, elt.GetProperty("number").GetInt64());
        //    Assert.True(elt.GetProperty("boolean").GetBoolean());
        //    Assert.Equal(1, elt.GetProperty("object").GetJsonDocument().RootElement.GetProperty("value").GetInt64());
        //    //Assert.Null(elt.GetProperty("null")());
        //}

        private HttpResponseMessage BackchannelRequestToken(HttpRequestMessage req)
        {
            if (req.RequestUri.AbsoluteUri == "https://demo.identityserver.io/.well-known/openid-configuration/jwks")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"6bbdca780af3a67163ca7531545da7a9\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                            Encoding.UTF8,
                            "application/json")
                };
            }
            throw new NotImplementedException(req.RequestUri.AbsoluteUri);
        }
    }

    public class JwtDocument3Tests : IClassFixture<KeyFixture>, IClassFixture<TokenFixture>
    {
        private readonly KeyFixture _keys;
        private readonly TokenFixture _tokens;

        public JwtDocument3Tests(KeyFixture keys, TokenFixture tokens)
        {
            _keys = keys;
            _tokens = tokens;
        }

        private class TokenSegment<T> : ReadOnlySequenceSegment<T>
        {
            public TokenSegment(ReadOnlyMemory<T> memory) => Memory = memory;

            public TokenSegment<T> Add(ReadOnlyMemory<T> mem)
            {
                var segment = new TokenSegment<T>(mem)
                {
                    RunningIndex = RunningIndex + Memory.Length
                };
                Next = segment;
                return segment;
            }
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_ValidMultipleSequence(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(jwt);

            TokenSegment<byte> firstSegment = new TokenSegment<byte>(utf8Jwt.AsMemory(0, 10));
            var secondSegment = firstSegment.Add(utf8Jwt.AsMemory(10, 10));
            var thirdSegment = secondSegment.Add(utf8Jwt.AsMemory(20));
            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(firstSegment, 0, thirdSegment, thirdSegment.Memory.Length);

            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument3.TryParse(sequence, builder, out var document);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_ValidSingleSequence(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(jwt);

            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(utf8Jwt);

            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument3.TryParse(sequence, builder, out var document);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_Valid(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = JwtDocument3.TryParse(jwt, builder, out var document);

            document.Payload.TryGetProperty("aud", out var aud);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwib2JqZWN0Ijp7ImhlbGxvIjoid29ybGQifSwiYXJyYXkiOlsiYSIsImIiLDEsMl0sIm51bWJlciI6MTIzLCJudWxsIjpudWxsLCJ0cnVlIjp0cnVlLCJmYWxzZSI6ZmFsc2V9.eyJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbS8iLCJleHAiOjI2MTYyMzkwMjIsIm5iZCI6MTUxNjIzOTAyMiwib2JqZWN0Ijp7ImhlbGxvIjoid29ybGQifSwiYXJyYXkiOlsiYSIsImIiLDEsMl0sIm51bWJlciI6MTIzLCJudWxsIjpudWxsLCJ0cnVlIjp0cnVlLCJmYWxzZSI6ZmFsc2V9.")]
        public void ReadJwt_Valid2(string jwt)
        {
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
                builder.AcceptUnsecureToken();

            var result = JwtDocument3.TryParse(jwt, builder, out var document);

            document.Payload.TryGetProperty("aud", out var aud);
            Assert.True(result);
        }

        [Theory]
        [ClassData(typeof(InvalidTokenTestData))]
        public void ReadJwt_Invalid(string jwt, TokenValidationStatus expectedStatus)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature(_keys.SigningKey)
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks)
                    .Build();

            var result = JwtDocument3.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(expectedStatus, document.Error.Status);
        }

        [Fact]
        public void ReadJwt_HttpKeyProvider_Valid()
        {
            var httpHandler = new TestHttpMessageHandler
            {
                Sender = BackchannelRequestToken
            };
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature("https://demo.identityserver.io/.well-known/openid-configuration/jwks", handler: httpHandler)
                    .Build();

            var jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1Mjc5NzMyNDIsImV4cCI6MTUyNzk3Njg0MiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19.PFI6Fl8J6nlk3MyDwUemy6e4GjtyNoDabuQcUdOoQRGUjVAhv0UKqSOujg4Y_g23nPCGGMNOVNDiyK9StV4NdUrPemdShR6gykKd-FE1n7uHEwN6vsTDV_EeoF5ZdQsqEVo8zxfWoCIVP2Llj7TTwaoNpnhl9fkHvCc75XqYyF7SkiQAXGGGTExNh12kEI_Hb_rZvjJN2HCw1BsMx9-KFM69oFhT8ClAXeG3j3YsQ9ffjoZXV31S2Llzk-5Mf6BrR5CpCUHWWbfnEU21ko2NH7Y_aBJOwVAxyadj-89RR3-Ixpz3mUDxsZ4nmhLJDbrM9e1SRUq-oPmljIp53j-NXg";
            var result = JwtDocument3.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1Mjc5NzMyNDIsImV4cCI6MTUyNzk3Njg0MiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19")]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0")]
        [InlineData("eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.")]
        [InlineData("....")]
        [InlineData("...")]
        [InlineData("..")]
        [InlineData(".")]
        [InlineData("")]
        public void ReadJwt_Malformed(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .Build();

            var result = JwtDocument3.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(TokenValidationStatus.MalformedToken, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl0sInVuZGVmaW5lZCI6IHRydWV9.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl0sInVuZGVmaW5lZCI6IHRydWV9.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl19.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl19.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiaW52YWxpZCJdLCJpbnZhbGlkIjogdHJ1ZX0.RkFJTA.", TokenValidationStatus.InvalidHeader, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiaW52YWxpZCJdLCJpbnZhbGlkIjogdHJ1ZX0.RkFJTA.", TokenValidationStatus.InvalidHeader, false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.RkFJTA.", TokenValidationStatus.MalformedToken, true)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.RkFJTA.", TokenValidationStatus.MalformedToken, false)]
        public void ReadJwt_CriticalHeader_Invalid(string jwt, TokenValidationStatus expected, bool headerCacheEnabled)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false));
            if (!headerCacheEnabled)
            {
                policy.DisabledHeaderCache();
            }

            var result = JwtDocument3.TryParse(jwt, policy.Build(), out var document);
            Assert.False(result);
            Assert.Equal(expected, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", true)]
        public void ReadJwt_CriticalHeader_Valid(string jwt, bool headerCacheEnabled)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false));
            if (!headerCacheEnabled)
            {
                policy.DisabledHeaderCache();
            }

            var result = JwtDocument3.TryParse(jwt, policy.Build(), out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDB9.")]
        public void Issue489_Valid(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .EnableLifetimeValidation()
                .Build();

            var result = JwtDocument3.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjE1MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.", TokenValidationStatus.Expired)]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6OTkwMDAwMDAwMH0.", TokenValidationStatus.NotYetValid)]
        [InlineData("eyJhbGciOiJub25lIn0.eyJuYmYiOjk5MDAwMDAwMDB9.", TokenValidationStatus.MissingClaim)]
        [InlineData("eyJhbGciOiJub25lIn0.e30.", TokenValidationStatus.MissingClaim)]
        public void Issue489_Invalid(string jwt, TokenValidationStatus status)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .EnableLifetimeValidation()
                .Build();

            var result = JwtDocument3.TryParse(jwt, policy, out var document);
            Assert.False(result);
            Assert.Equal(status, document.Error.Status);
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjE1MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6OTkwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJuYmYiOjk5MDAwMDAwMDB9.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDB9.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.e30.")]
        public void Issue489_NoValidation_Valid(string jwt)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureToken()
                .Build();

            var result = JwtDocument3.TryParse(jwt, policy, out var document);
            Assert.True(result);
        }

        //[Fact]
        //public void Parse()
        //{
        //    //var json = Encoding.UTF8.GetBytes("{\"string\":\"hello\",\"number\":1234,\"boolean\":true,\"object\":{\"value\":1},\"array\":[1,2,3,4],\"null\":null}");
        //    var json = Encoding.UTF8.GetBytes("{\"string\":\"hello\",\"number\":1234,\"boolean\":true,\"object\":{\"value\":1},\"null\":null}");

        //    var result = JwtPayloadDocument.Parse(json);
        //    var elt = result.RootElement;
        //    Assert.Equal("hello", elt.GetProperty("string").GetString());
        //    Assert.Equal(1234, elt.GetProperty("number").GetInt64());
        //    Assert.True(elt.GetProperty("boolean").GetBoolean());
        //    Assert.Equal(1, elt.GetProperty("object").GetJsonDocument().RootElement.GetProperty("value").GetInt64());
        //    //Assert.Null(elt.GetProperty("null")());
        //}

        private HttpResponseMessage BackchannelRequestToken(HttpRequestMessage req)
        {
            if (req.RequestUri.AbsoluteUri == "https://demo.identityserver.io/.well-known/openid-configuration/jwks")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"6bbdca780af3a67163ca7531545da7a9\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                            Encoding.UTF8,
                            "application/json")
                };
            }
            throw new NotImplementedException(req.RequestUri.AbsoluteUri);
        }
    }
}