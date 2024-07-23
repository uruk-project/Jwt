using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;
using Xunit.Sdk;

namespace JsonWebToken.Tests
{
    public class SecEventDescriptorTests : IClassFixture<KeyFixture>
    {
        [Fact]
        public void Write_Success()
        {
            var descriptor = new SecEventDescriptor()
            {
                Payload = new JwtPayload
                {
                    { "iss", "https://scim.example.com" },
                    { "iat", 1458496404 },
                    { "jti", "4d3559ec67504aaba65d40b0363faad8" },
                    { "aud", new [] { "https://scim.example.com/Feeds/98d52461fa5bbc879593b7754", "https://scim.example.com/Feeds/5d7604516b1d08641d7676ee7" } },
                    { "events", new JsonObject
                        {
                            { "urn:ietf:params:scim:event:create", new ScimCreateEvent
                                {
                                    Ref = "https://scim.example.com/Users/44f6142df96bd6ab61e7521d9",
                                    Attributes = { "id", "name", "userName", "password", "emails" }
                                }
                            }
                        }
                    }
                }
            };

            var writer = new JwtWriter();
            var jwt = writer.WriteTokenString(descriptor);

            AssertJwt.Equal("eyJhbGciOiJub25lIiwidHlwIjoic2VjZXZlbnQrand0In0.eyJpc3MiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20iLCJpYXQiOjE0NTg0OTY0MDQsImp0aSI6IjRkMzU1OWVjNjc1MDRhYWJhNjVkNDBiMDM2M2ZhYWQ4IiwiYXVkIjpbImh0dHBzOi8vc2NpbS5leGFtcGxlLmNvbS9GZWVkcy85OGQ1MjQ2MWZhNWJiYzg3OTU5M2I3NzU0IiwiaHR0cHM6Ly9zY2ltLmV4YW1wbGUuY29tL0ZlZWRzLzVkNzYwNDUxNmIxZDA4NjQxZDc2NzZlZTciXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OmNyZWF0ZSI6eyJyZWYiOiJodHRwczovL3NjaW0uZXhhbXBsZS5jb20vVXNlcnMvNDRmNjE0MmRmOTZiZDZhYjYxZTc1MjFkOSIsImF0dHJpYnV0ZXMiOlsiaWQiLCJuYW1lIiwidXNlck5hbWUiLCJwYXNzd29yZCIsImVtYWlscyJdfX19.", jwt);
        }

        [Fact]
        public void Validate_Fail()
        {
            var descriptor = CreateDescriptor(new MissingAttributeSecEvent());
            Assert.Throws<JwtDescriptorException>(() => descriptor.Validate());

            var descriptor2 = CreateDescriptor(new InvalidAttributeSecEvent());
            Assert.Throws<JwtDescriptorException>(() => descriptor2.Validate());
        }

        [Fact]
        public void Validate_Success()
        {
            var descriptor = CreateDescriptor(new ValidSecEvent());
            descriptor.Validate();
        }

        private static SecEventDescriptor CreateDescriptor(SecEvent evt)
        {
            return new SecEventDescriptor()
            {
                Payload = new JwtPayload
                {
                    { "iss", "https://scim.example.com" },
                    { "iat", 1458496404 },
                    { "jti", "4d3559ec67504aaba65d40b0363faad8" },
                    { "aud", new [] { "https://scim.example.com/Feeds/98d52461fa5bbc879593b7754", "https://scim.example.com/Feeds/5d7604516b1d08641d7676ee7" } },
                    { "events", new JsonObject
                        {
                            evt
                        }
                    }
                }
            };
        }

        private class ScimCreateEvent
        {
            private readonly List<string> _attributes = new List<string>();

            [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "ref", Required = Required.Default)]
            public string Ref { get; set; }

            [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "attributes", Required = Required.Default)]
            public IList<string> Attributes => _attributes;
        }

        public class MissingAttributeSecEvent : SecEvent
        {
            public override JsonEncodedText Name => JsonEncodedText.Encode("MissingAttribute");

            public override void Validate()
            {
                CheckRequiredMemberAsString(JsonEncodedText.Encode("XXX"));
            }
        }

        public class InvalidAttributeSecEvent : SecEvent
        {
            public override JsonEncodedText Name => JsonEncodedText.Encode("InvalidAttribute");

            public InvalidAttributeSecEvent()
            {
                Add("XXX", "this is a string");
            }

            public override void Validate()
            {
                CheckRequiredMemberAsInteger(JsonEncodedText.Encode("XXX"));
            }
        }
        public class ValidSecEvent : SecEvent
        {
            public override JsonEncodedText Name => JsonEncodedText.Encode("Valid");
            public ValidSecEvent()
            {
                Add("XXX", "this is a string");
            }

            public override void Validate()
            {
                CheckRequiredMemberAsString(JsonEncodedText.Encode("XXX"));
            }
        }
    }

    public static class AssertJwt
    {
        public static void Equal(string jwt1, string jwt2)
        {
            string[] parts1 = jwt1.Split('.');
            string[] parts2 = jwt2.Split('.');
            if (parts1.Length != parts2.Length)
            {
                throw new EqualException(jwt1, jwt2);
            }

            // This is a JWS
            if (parts1.Length == 3)
            {
                // assert the signature
                Assert.Equal(parts1[2], parts2[2]);

                // assert the header
                var rawHeader1 = Base64Url.Decode(parts1[0]);
                var header1 = JObject.Parse(Encoding.UTF8.GetString(rawHeader1));

                var rawHeader2 = Base64Url.Decode(parts2[0]);
                var header2 = JObject.Parse(Encoding.UTF8.GetString(rawHeader2));

                Assert.Equal(header1, header2);

                // assert the payload
                var rawPayload1 = Base64Url.Decode(parts1[1]);
                var payload1 = JObject.Parse(Encoding.UTF8.GetString(rawPayload1));
                var rawPayload2 = Base64Url.Decode(parts2[1]);
                var payload2 = JObject.Parse(Encoding.UTF8.GetString(rawPayload2));

                Assert.Equal(payload1, payload2);
            }
            else if (parts1.Length == 5)
            {
                // This is a JWE

                // assert the header
                var rawHeader1 = Base64Url.Decode(parts1[0]);
                var header1 = JObject.Parse(Encoding.UTF8.GetString(rawHeader1));

                var rawHeader2 = Base64Url.Decode(parts2[0]);
                var header2 = JObject.Parse(Encoding.UTF8.GetString(rawHeader2));

                Assert.Equal(header1, header2);

                // assert the encrypted key
                Assert.Equal(parts1[1], parts2[1]);
                // assert the IV
                Assert.Equal(parts1[2], parts2[2]);
                // assert the authentication tag
                Assert.Equal(parts1[4], parts2[4]);

                // assert the payload
                throw new NotSupportedException();
            }
            else
            {
                throw new NotSupportedException();
            }
        }
    }

}
