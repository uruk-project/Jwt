using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using JsonWebToken.Cryptography;
using Xunit;

namespace JsonWebToken.Tests
{
    public abstract class JwkTestsBase : IDisposable
    {
        private readonly List<IDisposable> _disposables = new List<IDisposable>();

        public virtual KeyWrapper CreateKeyWrapper_Succeed(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            bool created = key.TryGetKeyWrapper(enc, alg, out var keyWrapper);
            _disposables.Add(keyWrapper);
            Assert.True(created);
            Assert.NotNull(keyWrapper);
            return keyWrapper;
        }

        public virtual KeyWrapper CreateKeyWrapper_Failed(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            bool created = key.TryGetKeyWrapper(enc, alg, out var keyWrapper);
            _disposables.Add(keyWrapper);
            Assert.False(created);
            Assert.Null(keyWrapper);
            return keyWrapper;
        }

        public virtual Signer CreateSigner_Succeed(Jwk key, SignatureAlgorithm alg)
        {
            var created = key.TryGetSigner(alg, out var signer);
            _disposables.Add(signer);
            Assert.True(created);
            Assert.NotNull(signer);
            return signer;
        }

        public virtual Signer CreateSigner_Failed(Jwk key, SignatureAlgorithm alg)
        {
            var created = key.TryGetSigner(alg, out var signer);
            _disposables.Add(signer);
            Assert.False(created);
            Assert.Null(signer);
            return signer;
        }

        public abstract void Canonicalize();

        public Jwk CanonicalizeKey(Jwk key)
        {
            key.Kid = JsonEncodedText.Encode( "kid");
            key.Use = JwkUseValues.Sig;
            key.X5c.Add(new byte[0]);
            key.X5t = Base64Url.Decode("XOf1YEg_zFLX0PtGjiEVvjM1WsA");
            key.X5tS256 = Base64Url.Decode("ZgPMqAT8BELhXwBa2nIT0OvdWtQCiF_g09nAyHhgCe0");
            key.X5u = "https://example.com/jwks";
            var json = key.Canonicalize();
            var canonicalizedKey = Jwk.FromJson(Encoding.UTF8.GetString(json));
            Assert.NotNull(canonicalizedKey);

            Assert.True(canonicalizedKey.Alg.EncodedUtf8Bytes.IsEmpty);
            Assert.True(canonicalizedKey.Kid.EncodedUtf8Bytes.IsEmpty);
            Assert.True(canonicalizedKey.Use.EncodedUtf8Bytes.IsEmpty);
            Assert.Empty(canonicalizedKey.X5c);
            Assert.Null(canonicalizedKey.X5t);
            Assert.Null(canonicalizedKey.X5tS256);
            Assert.Null(canonicalizedKey.X5u);

            return canonicalizedKey;
        }

        public virtual void IsSupportedEncryption_Success(Jwk key, EncryptionAlgorithm enc)
        {
            Assert.True(key.SupportEncryption(enc));
        }

        public virtual void IsSupportedKeyWrapping_Success(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            Assert.True(key.SupportKeyManagement(alg));
        }

        public virtual void IsSupportedSignature_Success(Jwk key, SignatureAlgorithm alg)
        {
            Assert.True(key.SupportSignature(alg));
        }

        public void Dispose()
        {
            foreach (var item in _disposables)
            {
                item?.Dispose();
            }
        }

        public abstract void FromJson_WithProperties(string json);

        public abstract void WriteTo();
    }
}
