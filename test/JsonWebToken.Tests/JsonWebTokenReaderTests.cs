using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebTokenReaderTests : IClassFixture<KeyFixture>, IClassFixture<TokenFixture>
    {
        private readonly KeyFixture _keys;
        private readonly TokenFixture _tokens;

        public JsonWebTokenReaderTests(KeyFixture keys, TokenFixture tokens)
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

            var reader = new JwtReader(_keys.Jwks);
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/");
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = reader.TryReadToken(sequence, builder);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_ValidSingleSequence(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(jwt);

            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(utf8Jwt);

            var reader = new JwtReader(_keys.Jwks);
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/");
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = reader.TryReadToken(sequence, builder);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_Valid(string token, bool signed)
        {
            var jwt = _tokens.ValidTokens[token];
            var reader = new JwtReader(_keys.Jwks);
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/");
            if (signed)
            {
                builder.RequireSignature(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureToken();
            }

            var result = reader.TryReadToken(jwt, builder);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
        }

        [Theory]
        [ClassData(typeof(InvalidTokenTestData))]
        public void ReadJwt_Invalid(string jwt, TokenValidationStatus expectedStatus)
        {
            var reader = new JwtReader(_keys.Jwks);
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature(_keys.SigningKey)
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .RequireIssuer("https://idp.example.com/")
                    .Build();

            var result = reader.TryReadToken(jwt, policy);

            Assert.Equal(expectedStatus, result.Status);
        }

        [Fact]
        public void ReadJwt_HttpKeyProvider_Valid()
        {
            var httpHandler = new TestHttpMessageHandler
            {
                Sender = BackchannelRequestToken
            };
            var reader = new JwtReader(_keys.Jwks);
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignature("https://demo.identityserver.io/.well-known/openid-configuration/jwks", handler: httpHandler)
                    .Build();

            var jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1Mjc5NzMyNDIsImV4cCI6MTUyNzk3Njg0MiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19.PFI6Fl8J6nlk3MyDwUemy6e4GjtyNoDabuQcUdOoQRGUjVAhv0UKqSOujg4Y_g23nPCGGMNOVNDiyK9StV4NdUrPemdShR6gykKd-FE1n7uHEwN6vsTDV_EeoF5ZdQsqEVo8zxfWoCIVP2Llj7TTwaoNpnhl9fkHvCc75XqYyF7SkiQAXGGGTExNh12kEI_Hb_rZvjJN2HCw1BsMx9-KFM69oFhT8ClAXeG3j3YsQ9ffjoZXV31S2Llzk-5Mf6BrR5CpCUHWWbfnEU21ko2NH7Y_aBJOwVAxyadj-89RR3-Ixpz3mUDxsZ4nmhLJDbrM9e1SRUq-oPmljIp53j-NXg";
            var result = reader.TryReadToken(jwt, policy);
            Assert.Equal(TokenValidationStatus.Success, result.Status);
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
            var reader = new JwtReader(_keys.Jwks);
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .Build();

            var result = reader.TryReadToken(jwt, policy);
            Assert.Equal(TokenValidationStatus.MalformedToken, result.Status);
        }


        [Theory]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl0sInVuZGVmaW5lZCI6IHRydWV9.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsidW5kZWZpbmVkIl19.RkFJTA.", TokenValidationStatus.CriticalHeaderUnsupported)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiaW52YWxpZCJdLCJpbnZhbGlkIjogdHJ1ZX0.RkFJTA.", TokenValidationStatus.InvalidHeader)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.RkFJTA.", TokenValidationStatus.MalformedToken)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", TokenValidationStatus.Success)]
        public void ReadJwt_CriticalHeader(string jwt, TokenValidationStatus expected)
        {
            var reader = new JwtReader();
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureToken()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false))
                    .Build();

            var result = reader.TryReadToken(jwt, policy);
            Assert.Equal(expected, result.Status);
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

    public class ValidTokenTestData : IEnumerable<object[]>
    {
        private readonly TokenFixture _tokens;

        public ValidTokenTestData()
        {
            _tokens = new TokenFixture();
        }

        public IEnumerator<object[]> GetEnumerator()
        {
            foreach (var item in _tokens.ValidTokens.Where(t => !t.Key.EndsWith("empty")))
            {
                yield return new object[] { item.Key, !item.Key.StartsWith("JWT") };
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public class InvalidTokenTestData : IEnumerable<object[]>
    {
        private readonly TokenFixture _tokens;

        public InvalidTokenTestData()
        {
            _tokens = new TokenFixture();
        }

        public IEnumerator<object[]> GetEnumerator()
        {
            foreach (var item in _tokens.InvalidTokens)
            {
                yield return new object[] { item.Jwt, item.Status };
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public class TestHttpMessageHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage> Sender { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Sender != null)
            {
                return Task.FromResult(Sender(request));
            }

            return Task.FromResult<HttpResponseMessage>(null);
        }
    }

    public class TestCriticalHeaderHandler : ICriticalHeaderHandler
    {
        private readonly bool _value;

        public TestCriticalHeaderHandler(bool value)
        {
            _value = value;
        }

        public bool TryHandle(JwtHeader heade, string headerName)
        {
            return _value;
        }
    }
}