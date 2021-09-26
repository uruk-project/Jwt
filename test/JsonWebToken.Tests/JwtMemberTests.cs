﻿using System;
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
        public void Indexer_Array()
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes("{\"fake\":true, \"array\":[ 1, {}, {\"x\":true}, true, false, null, \"text\", [], [true, false]]}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("array", out var element);

            var value = element[0];
            Assert.Equal(JsonValueKind.Number, value.ValueKind);
            value = element[1];
            Assert.Equal(JsonValueKind.Object, value.ValueKind);
            value = element[2];
            Assert.Equal(JsonValueKind.Object, value.ValueKind);
            value = element[3];
            Assert.Equal(JsonValueKind.True, value.ValueKind);
            value = element[4];
            Assert.Equal(JsonValueKind.False, value.ValueKind);
            value = element[5];
            Assert.Equal(JsonValueKind.Null, value.ValueKind);
            value = element[6];
            Assert.Equal(JsonValueKind.String, value.ValueKind);
            value = element[7];
            Assert.Equal(JsonValueKind.Array, value.ValueKind);
            value = element[8];
            Assert.Equal(JsonValueKind.Array, value.ValueKind);
        }

        [Theory]
        [InlineData("{\"object\":{\"p1\":1, \"p2\":{}, \"p3\":{\"x\":true}, \"p4\":true, \"p5\":false, \"p6\":null, \"p7\":\"text\", \"p8\":[], \"p9\":[true, false]}}")]
        [InlineData("{\"placeholder\":true,\"object\":{\"p1\":1, \"p2\":{}, \"p3\":{\"x\":true}, \"p4\":true, \"p5\":false, \"p6\":null, \"p7\":\"text\", \"p8\":[], \"p9\":[true, false]}}")]
        [InlineData("{\"object\":{\"p1\":1, \"p2\":{}, \"p3\":{\"x\":true}, \"p4\":true, \"p5\":false, \"p6\":null, \"p7\":\"text\", \"p8\":[], \"p9\":[true, false]},\"placeholder\":true}")]
        [InlineData("{\"placeholder1\":true,\"object\":{\"p1\":1, \"p2\":{}, \"p3\":{\"x\":true}, \"p4\":true, \"p5\":false, \"p6\":null, \"p7\":\"text\", \"p8\":[], \"p9\":[true, false]},\"placeholder2\":true}")]
        public void Indexer_Object(string json)
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes(json), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("object", out var element);

            var value = element["p1"];
            var value2 = element[Encoding.UTF8.GetBytes("p1")];
            Assert.Equal(JsonValueKind.Number, value.ValueKind);
            Assert.Equal(JsonValueKind.Number, value2.ValueKind);
            value = element["p2"];
            value2 = element[Encoding.UTF8.GetBytes("p2")];
            Assert.Equal(JsonValueKind.Object, value.ValueKind);
            Assert.Equal(JsonValueKind.Object, value2.ValueKind);
            value = element["p3"];
            value2 = element[Encoding.UTF8.GetBytes("p3")];
            Assert.Equal(JsonValueKind.Object, value.ValueKind);
            Assert.Equal(JsonValueKind.Object, value2.ValueKind);
            value = element["p4"];
            value2 = element[Encoding.UTF8.GetBytes("p4")];
            Assert.Equal(JsonValueKind.True, value.ValueKind);
            Assert.Equal(JsonValueKind.True, value2.ValueKind);
            value = element["p5"];
            value2 = element[Encoding.UTF8.GetBytes("p5")];
            Assert.Equal(JsonValueKind.False, value.ValueKind);
            Assert.Equal(JsonValueKind.False, value2.ValueKind);
            value = element["p6"];
            value2 = element[Encoding.UTF8.GetBytes("p6")];
            Assert.Equal(JsonValueKind.Null, value.ValueKind);
            Assert.Equal(JsonValueKind.Null, value2.ValueKind);
            value = element["p7"];
            value2 = element[Encoding.UTF8.GetBytes("p7")];
            Assert.Equal(JsonValueKind.String, value.ValueKind);
            Assert.Equal(JsonValueKind.String, value2.ValueKind);
            value = element["p8"];
            value2 = element[Encoding.UTF8.GetBytes("p8")];
            Assert.Equal(JsonValueKind.Array, value.ValueKind);
            Assert.Equal(JsonValueKind.Array, value2.ValueKind);
            value = element["p9"];
            value2 = element[Encoding.UTF8.GetBytes("p9")];
            Assert.Equal(JsonValueKind.Array, value.ValueKind);
            Assert.Equal(JsonValueKind.Array, value2.ValueKind);
        }

        [Fact]
        public void EnumerateArrayOfObject()
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes("{\"array\":[ 1, {}, {\"x\":true}, true, false, null, \"text\", [], [true, false]]}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("array", out var element);

            var enumerator = element.EnumerateArray();
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Number, enumerator.Current.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Object, enumerator.Current.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Object, enumerator.Current.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.True, enumerator.Current.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.False, enumerator.Current.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Null, enumerator.Current.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.String, enumerator.Current.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Array, enumerator.Current.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Array, enumerator.Current.ValueKind);
        }

        [Fact]
        public void EnumerateArrayOfObject_NotAnArrayFail()
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes("{\"array\":{\"x\":true}}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("array", out var element);

            Assert.Throws<InvalidOperationException>(() => element.EnumerateArray());
        }

        [Fact]
        public void EnumerateArrayOfInteger()
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes("{\"array\":[1, 2, 3, 4, 5]}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("array", out var element);

            var enumerator = element.EnumerateArray<long>();
            enumerator.MoveNext();
            Assert.Equal(1, enumerator.Current.GetInt64());
            enumerator.MoveNext();
            Assert.Equal(2, enumerator.Current.GetInt64());
            enumerator.MoveNext();
            Assert.Equal(3, enumerator.Current.GetInt64());
            enumerator.MoveNext();
            Assert.Equal(4, enumerator.Current.GetInt64());
            enumerator.MoveNext();
            Assert.Equal(5, enumerator.Current.GetInt64());
        }

        [Fact]
        public void EnumerateArrayOfInteger_NotAnArray_Fail()
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes("{\"array\":{\"x\":1}}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("array", out var element);

            Assert.Throws<InvalidOperationException>(() => element.EnumerateArray<long>());
        }

        [Fact]
        public void EnumerateArrayOfString()
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes("{\"array\":[\"text1\", \"text2\", \"text3\", \"text4\", \"text5\"]}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("array", out var element);
            var enumerator = element.EnumerateArray<string>();
            enumerator.MoveNext();
            Assert.Equal("text1", enumerator.Current.GetString());
            enumerator.MoveNext();
            Assert.Equal("text2", enumerator.Current.GetString());
            enumerator.MoveNext();
            Assert.Equal("text3", enumerator.Current.GetString());
            enumerator.MoveNext();
            Assert.Equal("text4", enumerator.Current.GetString());
            enumerator.MoveNext();
            Assert.Equal("text5", enumerator.Current.GetString());
        }

        [Fact]
        public void EnumerateObjects()
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes("{\"object\":{\"p1\":1, \"p2\":{}, \"p3\":{\"x\":true}, \"p4\":true, \"p5\":false, \"p6\":null, \"p7\":\"text\", \"p8\":[], \"p8\":[true, false]}}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("object", out var element);

            var enumerator = element.EnumerateObject();
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Number, enumerator.Current.Value.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Object, enumerator.Current.Value.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Object, enumerator.Current.Value.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.True, enumerator.Current.Value.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.False, enumerator.Current.Value.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Null, enumerator.Current.Value.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.String, enumerator.Current.Value.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Array, enumerator.Current.Value.ValueKind);
            enumerator.MoveNext();
            Assert.Equal(JsonValueKind.Array, enumerator.Current.Value.ValueKind);
        }

        [Fact]
        public void EnumerateObjects_NoAnObject_Fail()
        {
            JwtHeaderDocument.TryParseHeader(Utf8.GetBytes("{\"object\":[1, 2, 3, 4, 5]}"), null, TokenValidationPolicy.NoValidation, out var header, out _);
            header.TryGetHeaderParameter("object", out var element);

            Assert.Throws<InvalidOperationException>(() => element.EnumerateObject());
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
