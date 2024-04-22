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
            string expected = "{\"long\":9223372036854775807,\"ulong\":18446744073709551615,\"int\":2147483647,\"uint\":4294967295,\"short\":32767,\"ushort\":65535,\"sbyte\":127,\"byte\":255,\"float\":3.4028235E+38,\"double\":1.7976931348623157E+308,\"true\":true,\"false\":false}";
#if NETCOREAPP2_2 || NET46_OR_GREATER
            expected = expected.Replace("\"float\":3.40282347E+38", "\"float\":3.4028235E+38");
#else
            Assert.Equal(expected, json);
#endif
        }
    }

    public class DescriptorTests
    {
        [Fact]
        public void Descriptor_SetInvalidHeader_ThrowException()
        {
            var descriptor = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None);
            Assert.Throws<ArgumentNullException>(() => descriptor.Header = null);
            descriptor.Header = new JwtHeader();
            Assert.Throws<InvalidOperationException>(() => descriptor.Header = new JwtHeader());
        }

        [Fact]
        public void Descriptor_AllKindOfObject()
        {
            var descriptor = new JweDescriptor(SymmetricJwk.GenerateKey(256), KeyManagementAlgorithm.Dir, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def)
            {
                Payload = new JwsDescriptor(SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256), SignatureAlgorithm.HS256)
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
            Assert.Equal(KeyManagementAlgorithm.Dir.Name, ((JsonEncodedText)jweHeaderParameter.Value));
            Assert.True(descriptor.Header.TryGetValue("enc", out jweHeaderParameter));
            Assert.Equal(EncryptionAlgorithm.A128CbcHS256.Name, ((JsonEncodedText)jweHeaderParameter.Value));
            Assert.True(descriptor.Header.TryGetValue("zip", out jweHeaderParameter));
            Assert.Equal(CompressionAlgorithm.Def.Name, (JsonEncodedText)jweHeaderParameter.Value);

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

            var descriptor = new JweDescriptor(SymmetricJwk.GenerateKey(EncryptionAlgorithm.A128CbcHS256), KeyManagementAlgorithm.Dir, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def)
            {
                Payload = new JwsDescriptor(SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256), SignatureAlgorithm.HS256)
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

        [Fact]
        public void Descriptor_SetPayloadNull_ThrowsArgumentNullException()
        {
            var payload = new JwtPayload();
            for (int i = 0; i < 16; i++)
            {
                payload.Add(i.ToString(), i);
            }

            SymmetricJwk encryptionKey = SymmetricJwk.GenerateKey(EncryptionAlgorithm.A128CbcHS256);
            SymmetricJwk signatureKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);

            Assert.Throws<ArgumentNullException>(() =>
                new JweDescriptor(encryptionKey, KeyManagementAlgorithm.Dir, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def)
                {
                    Payload = null
                });

            Assert.Throws<ArgumentNullException>(() =>
                new PlaintextJweDescriptor(encryptionKey, KeyManagementAlgorithm.Dir, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def)
                {
                    Payload = null
                });

            Assert.Throws<ArgumentNullException>(() =>
                new BinaryJweDescriptor(encryptionKey, KeyManagementAlgorithm.Dir, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def)
                {
                    Payload = null
                });

            Assert.Throws<ArgumentNullException>(() =>
                new JwkJweDescriptor(encryptionKey, KeyManagementAlgorithm.Dir, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def)
                {
                    Payload = null
                });

            Assert.Throws<ArgumentNullException>(() =>
                new JwksJweDescriptor(encryptionKey, KeyManagementAlgorithm.Dir, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def)
                {
                    Payload = null
                });

            Assert.Throws<ArgumentNullException>(() =>
                new JwsDescriptor(signatureKey, SignatureAlgorithm.HS256)
                {
                    Payload = null
                });
        }

        [Fact]
        public void Descriptor_PayloadSetTwice_PayloadNotChanged()
        {
            var descriptor = new JwsDescriptor(Jwk.None, SignatureAlgorithm.None);

            var payload1 = new JwtPayload { { "One", "Member" } };
            var json1 = payload1.ToString();
            descriptor.Payload = payload1;

            var payload2 = new JwtPayload { { "Something", "else" } };
            var json2 = payload2.ToString();
            descriptor.Payload = payload2;

            Assert.Equal(payload1.ToString(), json1);
            Assert.Equal(payload2.ToString(), json2);
        }

        public class Fake
        {
            public Fake Inner { get; set; }

            public string Value { get; set; }
        }

        [Fact]
        public void JwsDescriptor_Ctor()
        {
            SymmetricJwk signingKey = SymmetricJwk.GenerateKey(SignatureAlgorithm.HS256);
            Assert.Throws<ArgumentNullException>(() => new JwsDescriptor(null, SignatureAlgorithm.HS256));
            Assert.Throws<ArgumentNullException>(() => new JwsDescriptor(signingKey, null));

            var descriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HS256, "typ_value", "cty_value");
            Assert.Equal(signingKey, descriptor.SigningKey);
            Assert.Equal(SignatureAlgorithm.HS256, descriptor.Alg);
            Assert.True(descriptor.Header.TryGetValue("typ", out var typ));
            Assert.Equal("typ_value", (string)typ.Value);
            Assert.True(descriptor.Header.TryGetValue("cty", out var cty));
            Assert.Equal("cty_value", (string)cty.Value);

            var defaultDescriptor = new JwsDescriptor(signingKey, SignatureAlgorithm.HS256);
            Assert.False(defaultDescriptor.Header.TryGetValue("typ", out _));
            Assert.False(defaultDescriptor.Header.TryGetValue("cty", out _));
        }

        [Fact]
        public void JweDescriptor_Ctor()
        {
            SymmetricJwk encryptionKey = SymmetricJwk.GenerateKey(EncryptionAlgorithm.A128CbcHS256);
            Assert.Throws<ArgumentNullException>(() => new JweDescriptor(null, KeyManagementAlgorithm.A128KW, EncryptionAlgorithm.A128CbcHS256));
            Assert.Throws<ArgumentNullException>(() => new JweDescriptor(encryptionKey, null, EncryptionAlgorithm.A128CbcHS256));
            Assert.Throws<ArgumentNullException>(() => new JweDescriptor(encryptionKey, KeyManagementAlgorithm.A128KW, null));

            var descriptor = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.A128KW, EncryptionAlgorithm.A128CbcHS256, CompressionAlgorithm.Def, "typ_value", "cty_value");
            Assert.Equal(encryptionKey, descriptor.EncryptionKey);
            Assert.Equal(KeyManagementAlgorithm.A128KW, descriptor.Alg);
            Assert.Equal(EncryptionAlgorithm.A128CbcHS256, descriptor.Enc);
            Assert.Equal(CompressionAlgorithm.Def, descriptor.Zip);
            Assert.True(descriptor.Header.TryGetValue("typ", out var typ));
            Assert.Equal("typ_value", (string)typ.Value);
            Assert.True(descriptor.Header.TryGetValue("cty", out var cty));
            Assert.Equal("cty_value", (string)cty.Value);

            var descriptorDefault = new JweDescriptor(encryptionKey, KeyManagementAlgorithm.A128KW, EncryptionAlgorithm.A128CbcHS256);
            Assert.Equal(CompressionAlgorithm.NoCompression, descriptorDefault.Zip);
            Assert.False(descriptorDefault.Header.TryGetValue("typ", out _));
            Assert.True(descriptorDefault.Header.TryGetValue("cty", out cty));
            Assert.Equal("JWT", (string)cty.Value);
        }
    }
}