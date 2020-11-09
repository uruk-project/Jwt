using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwtPayloadTest
    {
        [Fact]
        public void ValueType()
        {
            var payload = new JwtPayload
            {
                { "long", long.MaxValue },
                { "ulong", ulong.MaxValue },
                { "int", int.MaxValue },
                { "uint", uint.MaxValue },
                { "short", short.MaxValue },
                { "ushort", ushort.MaxValue },
                { "sbyte", sbyte.MaxValue },
                { "byte", byte.MaxValue }
            };

            var stream = new MemoryStream();
            var writer = new Utf8JsonWriter(stream);
            payload.WriteTo(writer);
            writer.Flush();
            var json = Encoding.UTF8.GetString(stream.ToArray());
            Assert.Equal("{\"long\":9223372036854775807,\"ulong\":18446744073709551615,\"int\":2147483647,\"uint\":4294967295,\"short\":32767,\"ushort\":65535,\"sbyte\":127,\"byte\":255}", json);
        }
    }

    public class DescriptorTests
    {
        [Fact]
        public void Descriptor_AllKindOfObject()
        {
            var descriptor = new JweDescriptor
            {
                Alg = KeyManagementAlgorithm.Direct,
                Enc = EncryptionAlgorithm.Aes128CbcHmacSha256,
                EncryptionKey = SymmetricJwk.GenerateKey(256),
                Zip = CompressionAlgorithm.Deflate,
                Payload = new JwsDescriptor
                {
                    Alg = SignatureAlgorithm.HmacSha256,
                    SigningKey = SymmetricJwk.GenerateKey(256),
                    Header = new JwtHeader
                    {
                        { "H1", "value1" },
                        { "H2",  new Dictionary<string, object> { { "prop1", "value2" } } },
                        { "H3", 123L },
                        { "H4", new Fake { Inner = new Fake { Value = "Inner1", Inner = new Fake { Value = "Inner2" } }, Value = "Inner0" } },
                        { "H5", new [] { "a", "b", "c"} },
                        { "H6", new [] { new object(), new object(), "abc", 123 } },
                        { "H7", true },
                        { "H8", false },
                    },
                    Payload = new JwtPayload
                    {
                        { "P1", "value1" },
                        { "P2",  new Dictionary<string, object> { { "prop1", "value2" } } },
                        { "P3", 123L },
                        { "P4", new Fake { Inner = new Fake { Value = "Inner1", Inner = new Fake { Value = "Inner2" } }, Value = "Inner0" } },
                        { "P5", new [] { "a", "b", "c"} },
                        { "P6", new [] { new object(), new object(), "abc", 123 } },
                        { "P7", true },
                        { "P8", false },
                    }
                }
            };

            Assert.True(descriptor.Payload.TryGetValue("P1", out var claim));
            Assert.Equal(JsonValueKind.String, claim.Type);
            Assert.True(descriptor.Payload.TryGetValue("P2", out claim));
            Assert.Equal(JsonValueKind.Object, claim.Type);
            Assert.True(descriptor.Payload.TryGetValue("P3", out claim));
            Assert.Equal(JsonValueKind.Number, claim.Type);
            Assert.True(descriptor.Payload.TryGetValue("P4", out claim));
            Assert.Equal(JsonValueKind.Object, claim.Type);
            Assert.True(descriptor.Payload.TryGetValue("P5", out claim));
            Assert.Equal(JsonValueKind.Array, claim.Type);
            Assert.True(descriptor.Payload.TryGetValue("P6", out claim));
            Assert.Equal(JsonValueKind.Array, claim.Type);
            Assert.True(descriptor.Payload.TryGetValue("P7", out claim));
            Assert.Equal(JsonValueKind.True, claim.Type);
            Assert.True(descriptor.Payload.TryGetValue("P8", out claim));
            Assert.Equal(JsonValueKind.False, claim.Type);

            Assert.True(descriptor.Payload.Header.TryGetValue("alg", out var jwsHeaderParameter));
            Assert.Equal(JsonValueKind.String, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("kid", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.String, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H1", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.String, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H2", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.Object, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H3", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.Number, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H4", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.Object, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H5", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.Array, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H6", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.Array, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H7", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.True, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H8", out jwsHeaderParameter));
            Assert.Equal(JsonValueKind.False, jwsHeaderParameter.Type);

            Assert.True(descriptor.Header.TryGetValue("kid", out var jweHeaderParameter));
            Assert.True(descriptor.Header.TryGetValue("alg", out jweHeaderParameter));
            Assert.Equal(KeyManagementAlgorithm.Direct.Name, (string)jweHeaderParameter.Value);
            Assert.True(descriptor.Header.TryGetValue("enc", out jweHeaderParameter));
            Assert.Equal(EncryptionAlgorithm.Aes128CbcHmacSha256.Name, (string)jweHeaderParameter.Value);
            Assert.True(descriptor.Header.TryGetValue("zip", out jweHeaderParameter));
            Assert.Equal(CompressionAlgorithm.Deflate.Name, (string)jweHeaderParameter.Value);

            PooledByteBufferWriter writer = new PooledByteBufferWriter();
            var context = new EncodingContext(writer, null, 0, false);
            descriptor.Encode(context);
        }

        [Fact]
        public void Descriptor_FullCapacity()
        {
            var payload = new JwtPayload();
            for (int i = 0; i < 256; i++)
            {
                payload.Add(i.ToString(), i);
            }

            var descriptor = new JweDescriptor
            {
                Alg = KeyManagementAlgorithm.Direct,
                Enc = EncryptionAlgorithm.Aes128CbcHmacSha256,
                EncryptionKey = SymmetricJwk.GenerateKey(256),
                Zip = CompressionAlgorithm.Deflate,
                Payload = new JwsDescriptor
                {
                    Alg = SignatureAlgorithm.HmacSha256,
                    SigningKey = SymmetricJwk.GenerateKey(256),
                    Payload = payload
                }
            };

            for (int i = 0; i < 256; i++)
            {
                descriptor.Payload.TryGetValue(i.ToString(), out var member);
                Assert.Equal(JsonValueKind.Number, member.Type);
                Assert.Equal(i.ToString(), member.Name);
                Assert.Equal(i, (long)member.Value);
            }

            PooledByteBufferWriter writer = new PooledByteBufferWriter();
            var context = new EncodingContext(writer, null, 0, false);
            descriptor.Encode(context);
        }

        public class Fake
        {
            public Fake Inner { get; set; }

            public string Value { get; set; }
        }
    }
}