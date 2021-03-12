using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwksHttpKeyProviderTests
    {
        [Fact]
        public void GetKeys_ValidKid_ReturnsKeys()
        {
            var provider = new JwksHttpKeyProvider("https://example.com", "https://example.com/jwks", new TestHttpMessageHandler
            {
                Responses = new[]
                {
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1234\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    }
                }
            });

            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"1234\"}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            var keys = provider.GetKeys(header);
            Assert.Single(keys);
            Assert.Equal("1234", keys[0].Kid.ToString());
        }

        [Fact]
        public void GetKeys_InvalidKid_ReturnsEmpty()
        {
            var provider = new JwksHttpKeyProvider("https://example.com", "https://example.com/jwks", new TestHttpMessageHandler
            {
                Responses = new[]
                {
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1234\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    }
                }
            }, minimumRefreshInterval: 0);

            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"XXX\"}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            var keys = provider.GetKeys(header);
            Assert.Empty(keys);
        }

        [Fact]
        public void GetKeys_CachedButExpired_ReturnsRefreshedKeys()
        {
            var provider = new JwksHttpKeyProvider("https://example.com", "https://example.com/jwks", new TestHttpMessageHandler
            {
                Responses = new[]
                {
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[]}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1234\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    }
                }
            }, automaticRefreshInterval: 0);

            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"1234\"}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            var keys = provider.GetKeys(header);
            Assert.Empty(keys);

            keys = provider.GetKeys(header);
            Assert.Single(keys);
            Assert.Equal("1234", keys[0].Kid.ToString());
        }

        [Fact]
        public void GetKeys_CachedNotExpired_ReturnsEmpty()
        {
            var provider = new JwksHttpKeyProvider("https://example.com", "https://example.com/jwks", new TestHttpMessageHandler
            {
                Responses = new[]
                {
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[]}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[]}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1234\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    }
                }
            });

            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"1234\"}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            var keys = provider.GetKeys(header);
            Assert.Empty(keys);
            keys = provider.GetKeys(header);
            Assert.Empty(keys);
            keys = provider.GetKeys(header);
            Assert.Empty(keys);
        }

        [Fact]
        public void GetKeys_ForceRefresh_ReturnsRefreshedKeys()
        {
            var provider = new JwksHttpKeyProvider("https://example.com", "https://example.com/jwks", new TestHttpMessageHandler
            {
                Responses = new[]
                {
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[]}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1234\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    }
                }
            });

            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"1234\"}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            var keys = provider.GetKeys(header);
            Assert.Empty(keys);

            provider.ForceRefresh();
            keys = provider.GetKeys(header);
            Assert.Single(keys);
            Assert.Equal("1234", keys[0].Kid.ToString());
        }

        [Fact]
        public void GetKeys_Attacked_ReturnsPreviousKeys()
        {
            var provider = new JwksHttpKeyProvider("https://example.com", "https://example.com/jwks", new TestHttpMessageHandler
            {
                Responses = new[]
                {
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[]}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"XXX\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1234\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    }
                }
            });

            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"1234\"}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            var keys = provider.GetKeys(header);
            Assert.Empty(keys);
            keys = provider.GetKeys(header);
            Assert.Empty(keys);
            keys = provider.GetKeys(header);
            // The 3rd should be the good one, but the throttling will block this
            Assert.Empty(keys);
        }

        [Fact]
        public void GetKeys_NotFoundInKeyring_RefreshKeyring()
        {
            var provider = new JwksHttpKeyProvider("https://example.com", "https://example.com/jwks", new TestHttpMessageHandler
            {
                Responses = new[]
                {
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[]}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1234\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"XXX\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    }
                }
            }, minimumRefreshInterval: -1);

            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"1234\"}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            var keys = provider.GetKeys(header);
            Assert.Empty(keys);
            keys = provider.GetKeys(header);
            Assert.Single(keys);
            Assert.Equal("1234", keys[0].Kid.ToString());
            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"XXX\"}"), null, TokenValidationPolicy.NoValidation, out header, out _);
            keys = provider.GetKeys(header);
            Assert.Single(keys);
            Assert.Equal("XXX", keys[0].Kid.ToString());
        }

        [Fact]
        public void GetKeys_FromMetadata_ReturnsKeys()
        {
            var provider = new JwksHttpKeyProvider("https://example.com/.well-known/openid-configuration", new TestHttpMessageHandler
            {
                Responses = new[]
                {
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"issuer\":\"https://example.com\",\"jwks_uri\":\"https://example.com/jwks\"}",
                                Encoding.UTF8,
                                "application/json")
                    },
                    new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1234\",\"e\":\"AQAB\",\"n\":\"n6fNIStd3luK2mvco0ZnkDGE4JxB2FLmYtVJNyTmMfOj7CR5oM7vHSuOQYe17c8CUXBSCed5i6CmUyI59Vj4D2D2zdzqMiIyA5Y0djw5Js04QSvbXZId25YgMoHU0dichI1MmUYMPk5iQ_SwmSXsJKxwk1ytd1DciMxpCWkkAwJCAMoYR0_wcrtLX0M3i1sJthpCKle0-bj5YnhVE85vGeVrkvs9b8CKUCwqGruNptHtebpMKR1rBx1QXBTHHhXJjk5XQLu_S9_URuD0M6j__liGcjYzFEiz6b9NAjHHrraPfDfuKIgnHwpLFA-J8zjZeoXBstr9Mut_Gsgqmxg_cQ\",\"alg\":\"RS256\"}]}",
                                Encoding.UTF8,
                                "application/json")
                    }
                }
            });

            Assert.Equal("https://example.com", provider.Issuer);

            JwtHeaderDocument.TryParseHeader(Encoding.UTF8.GetBytes("{\"kid\":\"1234\"}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            var keys = provider.GetKeys(header);
            Assert.Single(keys);
            Assert.Equal("1234", keys[0].Kid.ToString());
        }

        public class TestHttpMessageHandler : HttpMessageHandler
        {
            private int _index = 0;

            public HttpResponseMessage[] Responses { get; set; }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (Responses != null)
                {
                    return Task.FromResult(Responses[_index++ % Responses.Length]);
                }

                return Task.FromResult<HttpResponseMessage>(null);
            }
        }
    }
}
