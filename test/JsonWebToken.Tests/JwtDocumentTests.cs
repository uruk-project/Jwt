﻿using System;
using System.Buffers;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwtTests : IClassFixture<KeyFixture>, IClassFixture<TokenFixture>
    {
        private readonly KeyFixture _keys;
        private readonly TokenFixture _tokens;

        public JwtTests(KeyFixture keys, TokenFixture tokens)
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
            var value = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(value);

            TokenSegment<byte> firstSegment = new TokenSegment<byte>(utf8Jwt.AsMemory(0, 10));
            var secondSegment = firstSegment.Add(utf8Jwt.AsMemory(10, 10));
            var thirdSegment = secondSegment.Add(utf8Jwt.AsMemory(20));
            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(firstSegment, 0, thirdSegment, thirdSegment.Memory.Length);

            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .DefaultIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignatureByDefault(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureTokenByDefault();
            }

            var result = Jwt.TryParse(sequence, builder.Build(), out var jwt);
            Assert.True(result);
            jwt.Dispose();
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_ValidSingleSequence(string token, bool signed)
        {
            var value = _tokens.ValidTokens[token];
            var utf8Jwt = Encoding.UTF8.GetBytes(value);

            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(utf8Jwt);

            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .DefaultIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignatureByDefault(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureTokenByDefault();
            }

            var result = Jwt.TryParse(sequence, builder.Build(), out var jwt);
            Assert.True(result);
            jwt.Dispose();
        }

        [Theory]
        [ClassData(typeof(ValidTokenTestData))]
        public void ReadJwt_Valid(string token, bool signed)
        {
            var value = _tokens.ValidTokens[token];
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .DefaultIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            if (signed)
            {
                builder.RequireSignatureByDefault(_keys.Jwks);
            }
            else
            {
                builder.AcceptUnsecureTokenByDefault();
            }

            var result = Jwt.TryParse(value, builder.Build(), out var jwt);

            Assert.True(result);
            Assert.True(jwt.Payload.TryGetClaim("aud", out var aud));
            Assert.Equal("636C69656E745F6964", aud.ValueKind == JsonValueKind.String ? aud.GetString() : aud.GetStringArray().First());
            Assert.True(jwt.Payload.TryGetClaim("iss", out var iss));
            Assert.Equal("https://idp.example.com/", iss.GetString());
            jwt.Dispose();
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwib2JqZWN0Ijp7ImhlbGxvIjoid29ybGQifSwiYXJyYXkiOlsiYSIsImIiLDEsMl0sIm51bWJlciI6MTIzLCJudWxsIjpudWxsLCJ0cnVlIjp0cnVlLCJmYWxzZSI6ZmFsc2V9.eyJhdWQiOiI2MzZDNjk2NTZFNzQ1RjY5NjQiLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbS8iLCJleHAiOjI2MTYyMzkwMjIsIm5iZCI6MTUxNjIzOTAyMiwib2JqZWN0Ijp7ImhlbGxvIjoid29ybGQifSwiYXJyYXkiOlsiYSIsImIiLDEsMl0sIm51bWJlciI6MTIzLCJudWxsIjpudWxsLCJ0cnVlIjp0cnVlLCJmYWxzZSI6ZmFsc2UsImVzY2FwZWRcdTAwNUMiOiB0cnVlfQ.")]
        public void ReadJwt_Valid2(string token)
        {
            var builder = new TokenValidationPolicyBuilder()
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .DefaultIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks);
            builder.AcceptUnsecureTokenByDefault();

            var result = Jwt.TryParse(token, builder.Build(), out var jwt);

            Assert.True(result);
            Assert.True(jwt.Payload.TryGetClaim("aud", out var aud));
            Assert.Equal("636C69656E745F6964", aud.GetString());
            Assert.True(jwt.Payload.TryGetClaim("iss", out var iss));
            Assert.Equal("https://idp.example.com/", iss.GetString());
            Assert.True(jwt.Payload.TryGetClaim("escaped\\", out var escaped));
            Assert.True(escaped.GetBoolean());

            jwt.Dispose();
        }

        [Theory]
        [ClassData(typeof(InvalidTokenTestData))]
        public void ReadJwt_Invalid(string token, TokenValidationStatus expectedStatus)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .RequireSignatureByDefault(_keys.SigningKey)
                    .EnableLifetimeValidation()
                    .RequireAudience("636C69656E745F6964")
                    .DefaultIssuer("https://idp.example.com/")
                    .WithDecryptionKeys(_keys.Jwks)
                    .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.False(result);
            Assert.Equal(expectedStatus, jwt.Error.Status);
            jwt.Dispose();
        }

        [Fact]
        public void ReadJwt_HttpKeyProvider_Valid()
        {
            var httpHandler = new TestHttpMessageHandler
            {
                Sender = BackchannelRequestToken
            };
            var policy = new TokenValidationPolicyBuilder()
                    .RequireMetadataConfiguration("https://demo.identityserver.io/.well-known/openid-configuration", SignatureAlgorithm.RS256, handler: httpHandler)
                    .Build();

            var token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYmRjYTc4MGFmM2E2NzE2M2NhNzUzMTU0NWRhN2E5IiwidHlwIjoiSldUIn0.eyJuYmYiOjE1Mjc5NzMyNDIsImV4cCI6MTUyNzk3Njg0MiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiY2xpZW50Iiwic2NvcGUiOlsiYXBpIl19.PFI6Fl8J6nlk3MyDwUemy6e4GjtyNoDabuQcUdOoQRGUjVAhv0UKqSOujg4Y_g23nPCGGMNOVNDiyK9StV4NdUrPemdShR6gykKd-FE1n7uHEwN6vsTDV_EeoF5ZdQsqEVo8zxfWoCIVP2Llj7TTwaoNpnhl9fkHvCc75XqYyF7SkiQAXGGGTExNh12kEI_Hb_rZvjJN2HCw1BsMx9-KFM69oFhT8ClAXeG3j3YsQ9ffjoZXV31S2Llzk-5Mf6BrR5CpCUHWWbfnEU21ko2NH7Y_aBJOwVAxyadj-89RR3-Ixpz3mUDxsZ4nmhLJDbrM9e1SRUq-oPmljIp53j-NXg";
            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.True(result);
            jwt.Dispose();
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
        public void ReadJwt_Malformed(string token)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureTokenByDefault()
                    .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.False(result);
            Assert.Equal(TokenValidationStatus.MalformedToken, jwt.Error.Status);
            jwt.Dispose();
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
        public void ReadJwt_CriticalHeader_Invalid(string token, TokenValidationStatus expected, bool headerCacheEnabled)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureTokenByDefault()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false));
            if (!headerCacheEnabled)
            {
                policy.DisableHeaderCache();
            }

            var result = Jwt.TryParse(token, policy.Build(), out var jwt);
            Assert.False(result);
            Assert.Equal(expected, jwt.Error.Status);
            jwt.Dispose();
        }

        [Theory]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", false)]
        [InlineData("eyJhbGciOiAibm9uZSIsImNyaXQiOlsiZXhwIl0sImV4cCI6IDEyMzR9.e30.", true)]
        public void ReadJwt_CriticalHeader_Valid(string token, bool headerCacheEnabled)
        {
            var policy = new TokenValidationPolicyBuilder()
                    .AcceptUnsecureTokenByDefault()
                    .AddCriticalHeaderHandler("exp", new TestCriticalHeaderHandler(true))
                    .AddCriticalHeaderHandler("invalid", new TestCriticalHeaderHandler(false));
            if (!headerCacheEnabled)
            {
                policy.DisableHeaderCache();
            }

            var result = Jwt.TryParse(token, policy.Build(), out var jwt);
            Assert.True(result);
            jwt.Dispose();
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDB9.")]
        public void Issue489_Valid(string token)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureTokenByDefault()
                .EnableLifetimeValidation()
                .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.True(result);
            jwt.Dispose();
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjE1MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.", TokenValidationStatus.Expired)]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6OTkwMDAwMDAwMH0.", TokenValidationStatus.NotYetValid)]
        [InlineData("eyJhbGciOiJub25lIn0.eyJuYmYiOjk5MDAwMDAwMDB9.", TokenValidationStatus.MissingClaim)]
        [InlineData("eyJhbGciOiJub25lIn0.e30.", TokenValidationStatus.MissingClaim)]
        public void Issue489_Invalid(string token, TokenValidationStatus status)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureTokenByDefault()
                .EnableLifetimeValidation()
                .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.False(result);
            Assert.Equal(status, jwt.Error.Status);
            jwt.Dispose();
        }

        [Theory]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjE1MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6OTkwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJuYmYiOjk5MDAwMDAwMDB9.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDB9.")]
        [InlineData("eyJhbGciOiJub25lIn0.eyJleHAiOjk5MDAwMDAwMDAsIm5iZiI6MTUwMDAwMDAwMH0.")]
        [InlineData("eyJhbGciOiJub25lIn0.e30.")]
        public void Issue489_NoValidation_Valid(string token)
        {
            var policy = new TokenValidationPolicyBuilder()
                .AcceptUnsecureTokenByDefault()
                .Build();

            var result = Jwt.TryParse(token, policy, out var jwt);
            Assert.True(result);
            jwt.Dispose();
        }

        [Fact]
        public void JwtHeaderDocument_TryParse()
        {
            var json = Encoding.UTF8.GetBytes("{\"string\":\"hello\",\"number\":1234,\"boolean\":true,\"object\":{\"value\":1},\"null\":null,\"array\":[\"hello\",\"world\"]}");

            var result = JwtHeaderDocument.TryParseHeader(json, null, TokenValidationPolicy.NoValidation, out var header, out var error);
            Assert.True(result);
            Assert.Equal("hello", GetProperty(header, "string").GetString());
            Assert.Equal(1234, GetProperty(header, "number").GetInt64());
            Assert.True(GetProperty(header, "boolean").GetBoolean());
            Assert.Equal(1, GetProperty(header, "object").GetJsonDocument().RootElement.GetProperty("value").GetInt64());
            Assert.NotNull(GetProperty(header, "array").GetJsonDocument().RootElement.EnumerateArray().ToArray());
            Assert.Equal(JsonValueKind.Null, GetProperty(header, "null").ValueKind);
            Assert.Null(error);
        }

        [Fact]
        public void JwtPayloadDocument_TryParse()
        {
            var json = Encoding.UTF8.GetBytes("{\"string\":\"hello\",\"number\":1234,\"boolean\":true,\"object\":{\"value\":1},\"null\":null,\"array\":[\"hello\",\"world\"]}");

            var result = JwtPayloadDocument.TryParsePayload(json, null, TokenValidationPolicy.NoValidation, out var payload, out var error);
            Assert.True(result);
            Assert.Equal("hello", GetProperty(payload, "string").GetString());
            Assert.Equal(1234, GetProperty(payload, "number").GetInt64());
            Assert.True(GetProperty(payload, "boolean").GetBoolean());
            Assert.Equal(1, GetProperty(payload, "object").GetJsonDocument().RootElement.GetProperty("value").GetInt64());
            Assert.NotNull(GetProperty(payload, "array").GetJsonDocument().RootElement.EnumerateArray().ToArray());
            Assert.Equal(JsonValueKind.Null, GetProperty(payload, "null").ValueKind);
            Assert.Null(error);
        }

        private static JwtElement GetProperty(JwtHeaderDocument document, string name)
            => document.TryGetHeaderParameter(name, out var value) ? value : default;

        private static JwtElement GetProperty(JwtPayloadDocument document, string name)
            => document.TryGetClaim(name, out var value) ? value : default;

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

            if (req.RequestUri.AbsoluteUri == "https://demo.identityserver.io/.well-known/openid-configuration")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"issuer\":\"https://demo.identityserver.io\",\"jwks_uri\":\"https://demo.identityserver.io/.well-known/openid-configuration/jwks\",\"authorization_endpoint\":\"https://demo.identityserver.io/connect/authorize\",\"token_endpoint\":\"https://demo.identityserver.io/connect/token\",\"userinfo_endpoint\":\"https://demo.identityserver.io/connect/userinfo\",\"end_session_endpoint\":\"https://demo.identityserver.io/connect/endsession\",\"check_session_iframe\":\"https://demo.identityserver.io/connect/checksession\",\"revocation_endpoint\":\"https://demo.identityserver.io/connect/revocation\",\"introspection_endpoint\":\"https://demo.identityserver.io/connect/introspect\",\"device_authorization_endpoint\":\"https://demo.identityserver.io/connect/deviceauthorization\",\"frontchannel_logout_supported\":true,\"frontchannel_logout_session_supported\":true,\"backchannel_logout_supported\":true,\"backchannel_logout_session_supported\":true,\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"api\",\"api.scope1\",\"api.scope2\",\"scope2\",\"policyserver.runtime\",\"policyserver.management\",\"offline_access\"],\"claims_supported\":[\"sub\",\"name\",\"family_name\",\"given_name\",\"middle_name\",\"nickname\",\"preferred_username\",\"profile\",\"picture\",\"website\",\"gender\",\"birthdate\",\"zoneinfo\",\"locale\",\"updated_at\",\"email\",\"email_verified\"],\"grant_types_supported\":[\"authorization_code\",\"client_credentials\",\"refresh_token\",\"implicit\",\"password\",\"urn:ietf:params:oauth:grant-type:device_code\"],\"response_types_supported\":[\"code\",\"token\",\"id_token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],\"response_modes_supported\":[\"form_post\",\"query\",\"fragment\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"subject_types_supported\":[\"public\"],\"code_challenge_methods_supported\":[\"plain\",\"S256\"],\"request_parameter_supported\":true}",
                            Encoding.UTF8,
                            "application/json")
                };
            }

            throw new NotImplementedException(req.RequestUri.AbsoluteUri);
        }
    }
}