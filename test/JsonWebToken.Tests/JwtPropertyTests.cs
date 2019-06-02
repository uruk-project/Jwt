using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwtPropertyTests
    {
        [Theory]
        [InlineData(WellKnownProperty.Alg, "alg")]
        [InlineData(WellKnownProperty.Aud, "aud")]
        [InlineData(WellKnownProperty.Cty, "cty")]
        [InlineData(WellKnownProperty.Enc, "enc")]
        [InlineData(WellKnownProperty.Exp, "exp")]
        [InlineData(WellKnownProperty.Iat, "iat")]
        [InlineData(WellKnownProperty.Iss, "iss")]
        [InlineData(WellKnownProperty.Jti, "jti")]
        [InlineData(WellKnownProperty.Kid, "kid")]
        [InlineData(WellKnownProperty.Nbf, "nbf")]
        [InlineData(WellKnownProperty.Sub, "sub")]
        [InlineData(WellKnownProperty.Typ, "typ")]
        [InlineData(WellKnownProperty.Zip, "zip")]
        public void GetWellKnowName(WellKnownProperty knownProperty, string expected)
        {
            var name = JwtProperty.GetWellKnowName(knownProperty);

            Assert.Equal(expected, Encoding.UTF8.GetString(name));
        }

        [Theory]
        [InlineData(WellKnownProperty.None)]
        public void GetWellKnowName_NotSupported(WellKnownProperty unknownProperty)
        {
            Assert.Throws<NotSupportedException>(() => JwtProperty.GetWellKnowName(unknownProperty));
        }

        [Theory]
        [MemberData(nameof(GetPropertiesToWrite))]
        public void WriteTo(JwtProperty property, string expected)
        {
            using (var bufferWriter = new ArrayBufferWriter<byte>())
            {
                var writer = new Utf8JsonWriter(bufferWriter);
                writer.WriteStartObject();
                property.WriteTo(ref writer);
                writer.WriteEndObject();
                writer.Flush();
                Assert.Equal(expected, Encoding.UTF8.GetString(bufferWriter.WrittenSpan));
            }
        }

        public static IEnumerable<object[]> GetPropertiesToWrite()
        {
            yield return new object[] { new JwtProperty("object", new JwtObject()), "{\"object\":{}}" };
            yield return new object[] { new JwtProperty("array", new JwtArray(new List<JwtValue>())), "{\"array\":[]}" };
            yield return new object[] { new JwtProperty("integer", 1L), "{\"integer\":1}" };
            yield return new object[] { new JwtProperty("integer", 1), "{\"integer\":1}" };
            yield return new object[] { new JwtProperty("float", 1.1), "{\"float\":1.1}" };
            yield return new object[] { new JwtProperty("string", "hello"), "{\"string\":\"hello\"}" };
            yield return new object[] { new JwtProperty("utf8String", new [] { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o' }), "{\"utf8String\":\"hello\"}" };
            yield return new object[] { new JwtProperty("boolean", true), "{\"boolean\":true}" };
            yield return new object[] { new JwtProperty("null"), "{\"null\":null}" };
        }
    }
}
