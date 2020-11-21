using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using JsonWebToken.Cryptography;
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
                { "byte", byte.MaxValue },
                { "float", float.MaxValue },
                { "double", double.MaxValue },
                { "true", true },
                { "false", false }
            };

            var stream = new MemoryStream();
            var writer = new Utf8JsonWriter(stream);
            payload.WriteTo(writer);
            writer.Flush();
            var json = Encoding.UTF8.GetString(stream.ToArray());
           // Assert.Equal("{\"long\":9223372036854775807,\"ulong\":18446744073709551615,\"int\":2147483647,\"uint\":4294967295,\"short\":32767,\"ushort\":65535,\"sbyte\":127,\"byte\":255,\"float\":3.4028235E+38,\"double\":1.7976931348623157E+308,\"true\":true,\"false\":false}", json);
        }
    }

    public class DescriptorTests
    {
        [Fact]
        public void Descriptor_AllKindOfObject()
        {
            var descriptor = new JweDescriptor(SymmetricJwk.GenerateKey(256), KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128CbcHmacSha256, CompressionAlgorithm.Deflate)
            {
                Payload = new JwsDescriptor(SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256), SignatureAlgorithm.HmacSha256)
                {
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

            Assert.True(descriptor.Payload.TryGetClaim("P1", out var claim));
            Assert.Equal(JwtValueKind.String, claim.Type);
            Assert.True(descriptor.Payload.TryGetClaim("P2", out claim));
            Assert.Equal(JwtValueKind.Object, claim.Type);
            Assert.True(descriptor.Payload.TryGetClaim("P3", out claim));
            Assert.Equal(JwtValueKind.Int64, claim.Type);
            Assert.True(descriptor.Payload.TryGetClaim("P4", out claim));
            Assert.Equal(JwtValueKind.Object, claim.Type);
            Assert.True(descriptor.Payload.TryGetClaim("P5", out claim));
            Assert.Equal(JwtValueKind.Array, claim.Type);
            Assert.True(descriptor.Payload.TryGetClaim("P6", out claim));
            Assert.Equal(JwtValueKind.Array, claim.Type);
            Assert.True(descriptor.Payload.TryGetClaim("P7", out claim));
            Assert.Equal(JwtValueKind.True, claim.Type);
            Assert.True(descriptor.Payload.TryGetClaim("P8", out claim));
            Assert.Equal(JwtValueKind.False, claim.Type);

            Assert.True(descriptor.Payload.Header.TryGetValue("alg", out var jwsHeaderParameter));
            Assert.Equal(JwtValueKind.JsonEncodedString, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("kid", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.JsonEncodedString, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H1", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.String, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H2", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.Object, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H3", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.Int64, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H4", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.Object, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H5", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.Array, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H6", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.Array, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H7", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.True, jwsHeaderParameter.Type);
            Assert.True(descriptor.Payload.Header.TryGetValue("H8", out jwsHeaderParameter));
            Assert.Equal(JwtValueKind.False, jwsHeaderParameter.Type);

            Assert.True(descriptor.Header.TryGetValue("kid", out var jweHeaderParameter));
            Assert.True(descriptor.Header.TryGetValue("alg", out jweHeaderParameter));
            Assert.Equal(KeyManagementAlgorithm.Direct.Name, ((JsonEncodedText)jweHeaderParameter.Value));
            Assert.True(descriptor.Header.TryGetValue("enc", out jweHeaderParameter));
            Assert.Equal(EncryptionAlgorithm.Aes128CbcHmacSha256.Name, ((JsonEncodedText)jweHeaderParameter.Value));
            Assert.True(descriptor.Header.TryGetValue("zip", out jweHeaderParameter));
            Assert.Equal(CompressionAlgorithm.Deflate.Name, (JsonEncodedText)jweHeaderParameter.Value);

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

            // TODO : SymmetricJwk.GenerateKey(EncryptionAlgorithm.Aes128CbcHmacSha256)
            var descriptor = new JweDescriptor(SymmetricJwk.GenerateKey(256), KeyManagementAlgorithm.Direct, EncryptionAlgorithm.Aes128CbcHmacSha256, CompressionAlgorithm.Deflate)
            {
                Payload = new JwsDescriptor(SymmetricJwk.GenerateKey(SignatureAlgorithm.HmacSha256), SignatureAlgorithm.HmacSha256)
                {
                    Payload = payload
                }
            };

            for (int i = 0; i < 256; i++)
            {
                descriptor.Payload.TryGetClaim(i.ToString(), out var member);
                Assert.Equal(JwtValueKind.Int32, member.Type);
                Assert.Equal(i.ToString(), member.Name.ToString());
                Assert.Equal(i, (int)member.Value);
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