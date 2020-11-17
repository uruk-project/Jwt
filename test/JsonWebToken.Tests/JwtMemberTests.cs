using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwtMemberTests
    {
        [Theory]
        [MemberData(nameof(GetPropertiesToWrite))]
        public void WriteTo(JwtMember property, string expected)
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
        
        [Fact]
        public void Ctor_NotSupported()
        {
            Assert.Throws<ArgumentNullException>(() => new JwtMember(JsonEncodedText.Encode("x"), (object)null));
        }

        public static IEnumerable<object[]> GetPropertiesToWrite()
        {
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("object"), new object()), "{\"object\":{}}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("array"), new List<object>()), "{\"array\":[]}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("int64"), 1L), "{\"int64\":1}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("int32"), 1), "{\"int32\":1}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("int16"), (short)1), "{\"int16\":1}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("int8"), (byte)1), "{\"int8\":1}" };
#if NETCOREAPP2_1 || NETFRAMEWORK || NETSTANDARD
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("float"), 1.0f), "{\"float\":1}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("float"), 1.1f), "{\"float\":" + ((double)1.1f).ToString("G9", CultureInfo.InvariantCulture) + "}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("double"), 1.0d), "{\"double\":1}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("double"), 1.1d), "{\"double\":" + (1.1d).ToString("G17", CultureInfo.InvariantCulture) + "}" };
#else
            byte[] destination = new byte[256];
            Utf8Formatter.TryFormat(1.0f, destination, out int bytesWritten);
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("float"), 1.0f), "{\"float\":" + Encoding.UTF8.GetString(destination.AsSpan().Slice(0, bytesWritten)) + "}" };
            Utf8Formatter.TryFormat(1.1f, destination, out bytesWritten);
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("float"), 1.1f), "{\"float\":" + Encoding.UTF8.GetString(destination.AsSpan().Slice(0, bytesWritten)) + "}" };
            Utf8Formatter.TryFormat(1.0d, destination, out bytesWritten);
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("double"), 1.0d), "{\"double\":" + Encoding.UTF8.GetString(destination.AsSpan().Slice(0, bytesWritten)) + "}" };
            Utf8Formatter.TryFormat(1.1d, destination, out bytesWritten);
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("double"), 1.1d), "{\"double\":" + Encoding.UTF8.GetString(destination.AsSpan().Slice(0, bytesWritten)) + "}" };
#endif
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("string"), "hello"), "{\"string\":\"hello\"}" };
            //yield return new object[] { new JwtMember("utf8String", new[] { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o' }), "{\"utf8String\":\"hello\"}" };
            yield return new object[] { new JwtMember(JsonEncodedText.Encode("boolean"), true), "{\"boolean\":true}" };
        }
    }
}
