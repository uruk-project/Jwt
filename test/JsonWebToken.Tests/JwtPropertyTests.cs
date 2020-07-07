using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Xunit;
using System.Buffers.Text;

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

            Assert.Equal(expected, Encoding.UTF8.GetString(name.ToArray()));
        }

        [Theory]
        [InlineData(WellKnownProperty.None)]
        public void GetWellKnowName_NotSupported(WellKnownProperty unknownProperty)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => JwtProperty.GetWellKnowName(unknownProperty));
        }

        [Theory]
        [MemberData(nameof(GetPropertiesToWrite))]
        public void WriteTo(JwtProperty property, string expected)
        {
            using (var bufferWriter = new PooledByteBufferWriter())
            {
                using (var writer = new Utf8JsonWriter(bufferWriter))
                {
                    writer.WriteStartObject();
                    property.WriteTo(writer);
                    writer.WriteEndObject();
                }

                string json = Encoding.UTF8.GetString(bufferWriter.WrittenSpan.ToArray());
                Assert.Equal(expected, json);
            }
        }

        public static IEnumerable<object[]> GetPropertiesToWrite()
        {
            yield return new object[] { new JwtProperty("object", new JwtObject()), "{\"object\":{}}" };
            yield return new object[] { new JwtProperty("array", new JwtArray(new List<JwtValue>())), "{\"array\":[]}" };
            yield return new object[] { new JwtProperty("int64", 1L), "{\"int64\":1}" };
            yield return new object[] { new JwtProperty("int32", 1), "{\"int32\":1}" };
            yield return new object[] { new JwtProperty("int16", (short)1), "{\"int16\":1}" };
            yield return new object[] { new JwtProperty("int8", (byte)1), "{\"int8\":1}" };
#if NETCOREAPP && !NETCORAPP2_1
            yield return new object[] { new JwtProperty("float", 1.0f), "{\"float\":1}" };
            yield return new object[] { new JwtProperty("float", 1.1f), "{\"float\":" + (1.1f).ToString("G9", CultureInfo.InvariantCulture) + "}" };
            yield return new object[] { new JwtProperty("double", 1.0d), "{\"double\":1}" };
            yield return new object[] { new JwtProperty("double", 1.1d), "{\"double\":" + (1.1d).ToString("G17", CultureInfo.InvariantCulture) + "}" };
#else
            byte[] destination = new byte[256];
            Utf8Formatter.TryFormat(1.0f, destination, out int bytesWritten);
            yield return new object[] { new JwtProperty("float", 1.0f), "{\"float\":" + Encoding.UTF8.GetString(destination.AsSpan().Slice(0, bytesWritten)) + "}" };
            Utf8Formatter.TryFormat(1.1f, destination, out  bytesWritten);
            yield return new object[] { new JwtProperty("float", 1.1f), "{\"float\":" + Encoding.UTF8.GetString(destination.AsSpan().Slice(0, bytesWritten)) + "}" };
            Utf8Formatter.TryFormat(1.0d, destination, out bytesWritten);
            yield return new object[] { new JwtProperty("double", 1.0d), "{\"double\":" + Encoding.UTF8.GetString(destination.AsSpan().Slice(0, bytesWritten)) + "}" };
            Utf8Formatter.TryFormat(1.1d, destination, out bytesWritten);
            yield return new object[] { new JwtProperty("double", 1.1d), "{\"double\":" + Encoding.UTF8.GetString(destination.AsSpan().Slice(0, bytesWritten)) + "}" };
#endif
            yield return new object[] { new JwtProperty("string", "hello"), "{\"string\":\"hello\"}" };
            yield return new object[] { new JwtProperty("utf8String", new[] { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o' }), "{\"utf8String\":\"hello\"}" };
            yield return new object[] { new JwtProperty("boolean", true), "{\"boolean\":true}" };
            yield return new object[] { new JwtProperty("null"), "{\"null\":null}" };
        }
    }
}
