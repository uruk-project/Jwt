using System;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JwtBuilderTests
    {
        [Fact]
        public void Build_Jwe()
        {
            var builder = new JwtDescriptorBuilder();

            builder
                .SignWith(RsaJwk.GenerateKey(2048, true, SignatureAlgorithm.RsaSsaPssSha256.Name))
                .EncryptWith(SymmetricJwk.GenerateKey(128))
                .IssuedBy("https://issuer.example.com")
                .Expires(DateTime.UtcNow);

            var descriptor = builder.Build();

            Assert.IsType<JweDescriptor>(descriptor);
        }

        [Fact]
        public void Build_Jws()
        {
            var builder = new JwtDescriptorBuilder();

            builder
                .SignWith(RsaJwk.GenerateKey(2048, true, SignatureAlgorithm.RsaSsaPssSha256.Name))
                .IssuedBy("https://issuer.example.com")
                .Expires(DateTime.UtcNow);

            var descriptor = builder.Build();

            Assert.IsType<JwsDescriptor>(descriptor);
        }

        [Fact]
        public void Build_Jwt_Unsigned()
        {
            var builder = new JwtDescriptorBuilder();

            builder
                .IgnoreSignature()
                .IssuedBy("https://issuer.example.com")
                .Expires(DateTime.UtcNow);

            var descriptor = builder.Build();

            Assert.IsType<JwsDescriptor>(descriptor);
        }

        [Fact]
        public void Build_BinaryJwt()
        {
            var builder = new JwtDescriptorBuilder();

            builder
                .EncryptWith(SymmetricJwk.GenerateKey(128))
                .Binary(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });

            var descriptor = builder.Build();

            Assert.IsType<BinaryJweDescriptor>(descriptor);
        }

        [Fact]
        public void Build_TextJwt()
        {
            var builder = new JwtDescriptorBuilder();

            builder
                .Plaintext("Live long and prosper.")
                .EncryptWith(SymmetricJwk.GenerateKey(128));

            var descriptor = builder.Build();

            Assert.IsType<PlaintextJweDescriptor>(descriptor);
        }
    }
}
