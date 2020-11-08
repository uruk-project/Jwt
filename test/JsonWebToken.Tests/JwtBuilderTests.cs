//using System;
//using JsonWebToken.Internal;
//using Xunit;

//namespace JsonWebToken.Tests
//{
//    public class JwtBuilderTests
//    {
//        [Fact]
//        public void Build_Jwe()
//        {
//            var builder = new JwtDescriptorBuilder();

//            var now = EpochTime.ToDateTime(EpochTime.UtcNow);
//            builder
//                .SignWith(RsaJwk.GenerateKey(2048, true, SignatureAlgorithm.RsaSsaPssSha256))
//                .EncryptWith(SymmetricJwk.GenerateKey(128), EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Direct)
//                .IssuedBy("https://issuer.example.com")
//                .ExpiresAt(now);

//            var descriptor = builder.Build();

//            Assert.IsType<Old_JweDescriptor>(descriptor);
//            var jwe = (Old_JweDescriptor)descriptor;
//            Assert.Equal("https://issuer.example.com", jwe.Payload.Issuer);
//            Assert.Equal(now, jwe.Payload.ExpirationTime);
//            Assert.Equal(SignatureAlgorithm.RsaSsaPssSha256, jwe.Payload.Algorithm);
//            Assert.Equal(KeyManagementAlgorithm.Direct, jwe.Algorithm);
//            Assert.Equal(EncryptionAlgorithm.Aes128CbcHmacSha256, jwe.EncryptionAlgorithm);
//        }

//        [Fact]
//        public void Build_Jws()
//        {
//            var builder = new JwtDescriptorBuilder();

//            var now = EpochTime.ToDateTime(EpochTime.UtcNow);
//            builder
//                .SignWith(RsaJwk.GenerateKey(2048, true, SignatureAlgorithm.RsaSsaPssSha256))
//                .IssuedBy("https://issuer.example.com")
//                .ExpiresAt(now);

//            var descriptor = builder.Build();

//            Assert.IsType<Old_JwsDescriptor>(descriptor);
//            var jws = (Old_JwsDescriptor)descriptor;
//            Assert.Equal("https://issuer.example.com", jws.Issuer);
//            Assert.Equal(now, jws.ExpirationTime);
//            Assert.Null(jws.JwtId);
//            Assert.Null(jws.IssuedAt);
//            Assert.Null(jws.NotBefore);
//            Assert.Null(jws.Subject);
//            Assert.Null(jws.KeyId);
//            Assert.Null(jws.Audience);
//            Assert.Equal(SignatureAlgorithm.RsaSsaPssSha256, jws.Algorithm);
//        }

//        [Fact]
//        public void Build_Jws_AutomaticClaims()
//        {
//            var builder = new JwtDescriptorBuilder();

//            var now = EpochTime.ToDateTime(EpochTime.UtcNow);
//            builder
//                .SignWith(RsaJwk.GenerateKey(2048, true, SignatureAlgorithm.RsaSsaPssSha256))
//                .ExpiresAfter(10)
//                .NotBefore(5)
//                .WithAutomaticId()
//                .WithAutomaticIssuedAt();

//            var descriptor = builder.Build();

//            Assert.IsType<Old_JwsDescriptor>(descriptor);
//            var jws = (Old_JwsDescriptor)descriptor;
//            Assert.NotNull(jws.ExpirationTime);
//            Assert.InRange((jws.ExpirationTime - now).Value.TotalSeconds - 10, -10, 10);
//            Assert.NotNull(jws.JwtId);
//            Assert.NotNull(jws.IssuedAt);
//            Assert.InRange((jws.IssuedAt - now).Value.TotalSeconds, -10, 10);
//            Assert.NotNull(jws.NotBefore);
//            Assert.InRange((jws.NotBefore - now).Value.TotalSeconds - 5, -10, 10);
//            Assert.Null(jws.Subject);
//            Assert.Null(jws.KeyId);
//            Assert.Null(jws.Audience);
//            Assert.Equal(SignatureAlgorithm.RsaSsaPssSha256, jws.Algorithm);
//        }

//        [Fact]
//        public void Build_Jwt_Unsigned()
//        {
//            var builder = new JwtDescriptorBuilder();

//            var now = EpochTime.ToDateTime(EpochTime.UtcNow);
//            builder
//                .IgnoreSignature()
//                .IssuedBy("https://issuer.example.com")
//                .ExpiresAt(DateTime.UtcNow);

//            var descriptor = builder.Build();

//            Assert.IsType<Old_JwsDescriptor>(descriptor);

//            Assert.IsType<Old_JwsDescriptor>(descriptor);
//            var jws = (Old_JwsDescriptor)descriptor;
//            Assert.Equal("https://issuer.example.com", jws.Issuer);
//            Assert.Equal(now, jws.ExpirationTime);
//            Assert.Equal(SignatureAlgorithm.None, jws.Algorithm);
//        }

//        [Fact]
//        public void Build_BinaryJwt()
//        {
//            var builder = new JwtDescriptorBuilder();

//            builder
//                .EncryptWith(SymmetricJwk.GenerateKey(128), EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Direct)
//                .BinaryPayload(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });

//            var descriptor = builder.Build();

//            Assert.IsType<BinaryJweDescriptor>(descriptor);
//            var binary = (BinaryJweDescriptor)descriptor;
//            Assert.Equal(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, binary.Payload);

//            Assert.Equal(KeyManagementAlgorithm.Direct, binary.Algorithm);
//            Assert.Equal(EncryptionAlgorithm.Aes128CbcHmacSha256, binary.EncryptionAlgorithm);
//        }

//        [Fact]
//        public void Build_TextJwt()
//        {
//            var builder = new JwtDescriptorBuilder();

//            builder
//                .PlaintextPayload("Live long and prosper.")
//                .EncryptWith(SymmetricJwk.GenerateKey(128), EncryptionAlgorithm.Aes128CbcHmacSha256, KeyManagementAlgorithm.Direct);

//            var descriptor = builder.Build();

//            Assert.IsType<PlaintextJweDescriptor>(descriptor);
//            var plaintext = (PlaintextJweDescriptor)descriptor;
//            Assert.Equal("Live long and prosper.", plaintext.Payload);

//            Assert.Equal(KeyManagementAlgorithm.Direct, plaintext.Algorithm);
//            Assert.Equal(EncryptionAlgorithm.Aes128CbcHmacSha256, plaintext.EncryptionAlgorithm);
//        }

//        [Fact]
//        public void Build_Jws_MissingSigningKey()
//        {
//            var builder = new JwtDescriptorBuilder();

//            var now = EpochTime.ToDateTime(EpochTime.UtcNow);
//            builder
//                .IssuedBy("https://issuer.example.com")
//                .ExpiresAt(now);

//            var exception = Assert.Throws<InvalidOperationException>(() => builder.Build());
//            Assert.Contains("No signing key is defined.", exception.Message);
//        }

//        [Fact]
//        public void Build_Jws_MissingSigningAlgorithm()
//        {
//            var builder = new JwtDescriptorBuilder();

//            var now = EpochTime.ToDateTime(EpochTime.UtcNow);
//            builder
//                .IssuedBy("https://issuer.example.com")
//                .ExpiresAt(now)
//                .SignWith(SymmetricJwk.GenerateKey(128));

//            var exception = Assert.Throws<InvalidOperationException>(() => builder.Build());
//            Assert.Contains("No algorithm is defined for the signature.", exception.Message);
//        }

//        [Fact]
//        public void Build_Jws_NoneWithSigningKey()
//        {
//            var builder = new JwtDescriptorBuilder();

//            var now = EpochTime.ToDateTime(EpochTime.UtcNow);
//            builder
//                .IssuedBy("https://issuer.example.com")
//                .ExpiresAt(now)
//                .SignWith(SymmetricJwk.GenerateKey(128), SignatureAlgorithm.None);

//            var exception = Assert.Throws<InvalidOperationException>(() => builder.Build());
//            Assert.Contains("The algorithm 'none' defined with a signing key.", exception.Message);
//        }

//        [Fact]
//        public void Build_JweMissingKeyManagementAlgorithm()
//        {
//            var builder = new JwtDescriptorBuilder();

//            var now = EpochTime.ToDateTime(EpochTime.UtcNow);
//            builder
//                .SignWith(RsaJwk.GenerateKey(2048, true, SignatureAlgorithm.RsaSsaPssSha256))
//                .EncryptWith(SymmetricJwk.GenerateKey(128), EncryptionAlgorithm.Aes128CbcHmacSha256)
//                .IssuedBy("https://issuer.example.com")
//                .ExpiresAt(now);

//            var exception = Assert.Throws<InvalidOperationException>(() => builder.Build());
//            Assert.Contains("No algorithm is defined for the key management encryption.", exception.Message);
//        }
//    }
//}
