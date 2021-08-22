using System;
using System.Collections.Generic;
using Xunit;

namespace JsonWebToken.Tests
{
    public class TokenValidationPolicyBuilderTests
    {
        [Fact]
        public void BuilderFails()
        {
            var builder = new TokenValidationPolicyBuilder();
            Assert.Throws<ArgumentNullException>(() => builder.AddValidator(null));
            Assert.Throws<ArgumentOutOfRangeException>(() => builder.MaximumTokenSizeInBytes(-1));
            Assert.Throws<InvalidOperationException>(() => builder.RequireMetadataConfiguration("jwks_uri", SignatureAlgorithm.HS256));
            Assert.Throws<ArgumentNullException>(() => builder.RequireSignature("issuer", (Jwk)null, SignatureAlgorithm.HS256));
            Assert.Throws<InvalidOperationException>(() => builder.RequireSignature("issuer", SymmetricJwk.GenerateKey(128), (SignatureAlgorithm)null));

            Assert.Throws<ArgumentNullException>(() => builder.RequireSignature("issuer", (Jwks)null, SignatureAlgorithm.HS256));
            Assert.Throws<ArgumentException>(() => builder.RequireSignature("issuer", new StaticKeyProvider(new Jwks(SymmetricJwk.GenerateKey(128))), SignatureAlgorithm.None));
            Assert.Throws<ArgumentNullException>(() => builder.RequireSignature("issuer", new StaticKeyProvider(new Jwks(SymmetricJwk.GenerateKey(128))), (SignatureAlgorithm)null));
            Assert.Throws<ArgumentNullException>(() => builder.RequireSignature("issuer",  (StaticKeyProvider)null, SignatureAlgorithm.HS256));
            Assert.Throws<ArgumentNullException>(() => builder.RequireSignature(null, new StaticKeyProvider(new Jwks(SymmetricJwk.GenerateKey(128))), SignatureAlgorithm.HS256));
            Assert.Throws<ArgumentNullException>(() => builder.IgnoreSignature(null));
            Assert.Throws<ArgumentNullException>(() => builder.AcceptUnsecureToken(null));
            Assert.Throws<ArgumentNullException>(() => builder.RequireSignatureByDefault((IKeyProvider)null));
            Assert.Throws<ArgumentNullException>(() => builder.RequireSignatureByDefault((Jwk)null));
            Assert.Throws<InvalidOperationException>(() => builder.RequireSignatureByDefault(SymmetricJwk.GenerateKey(128)));
            Assert.Throws<ArgumentNullException>(() => builder.RequireSignatureByDefault(SymmetricJwk.GenerateKey(128), (string)null));
            Assert.Throws<NotSupportedException>(() => builder.RequireSignatureByDefault(SymmetricJwk.GenerateKey(128), ""));
            Assert.Throws<NotSupportedException>(() => builder.RequireSignatureByDefault((Jwk)null, ""));
            Assert.Throws<ArgumentNullException>(() => builder.RequireSignatureByDefault((IList<Jwk>)null));
            Assert.Throws<ArgumentOutOfRangeException>(() => builder.EnableLifetimeValidation(clockSkew: -1));
            Assert.Throws<ArgumentNullException>(() => builder.RequireAudience((string)null));
            Assert.Throws<ArgumentNullException>(() => builder.RequireAudience((IEnumerable<string>)null));
            Assert.Throws<ArgumentNullException>(() => builder.DefaultIssuer(null));
            Assert.Throws<ArgumentNullException>(() => builder.EnableTokenReplayValidation(null));
            Assert.Throws<ArgumentNullException>(() => builder.RequireAlgorithm(null));
            Assert.Throws<ArgumentNullException>(() => builder.WithDecryptionKeys((ICollection<IKeyProvider>)null));
        }
    }
}
