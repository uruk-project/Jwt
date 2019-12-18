﻿using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace JsonWebToken.Tests
{
    public abstract class JwkTestsBase : IDisposable
    {
        private readonly List<IDisposable> _disposables = new List<IDisposable>();

        public virtual AuthenticatedEncryptor CreateAuthenticatedEncryptor_Succeed(Jwk key, EncryptionAlgorithm enc)
        {
            var created = key.TryGetAuthenticatedEncryptor(enc, out var encryptor);
            _disposables.Add(encryptor);
            Assert.True(created);
            Assert.NotNull(encryptor);
            return encryptor;
        }

        public virtual KeyWrapper CreateKeyWrapper_Succeed(Jwk key, EncryptionAlgorithm enc, KeyManagementAlgorithm alg)
        {
            bool created = key.TryGetKeyWrapper(enc, alg, out var keyWrapper);
            _disposables.Add(keyWrapper);
            Assert.True(created);
            Assert.NotNull(keyWrapper);
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

        public abstract void Canonicalize();

        public Jwk CanonicalizeKey(Jwk key)
        {
            key.Alg = SignatureAlgorithm.HmacSha256.Utf8Name;
            key.Kid = "kid";
            key.Use = JwkUseNames.Sig.ToArray();
            key.X5c.Add(new byte[0]);
            key.X5t = Encoding.UTF8.GetBytes("x5t");
            key.X5tS256 = Encoding.UTF8.GetBytes("x5t#256");
            key.X5u = "https://example.com/jwks";
            var json = key.Canonicalize();
            var canonicalizedKey = Jwk.FromJson(Encoding.UTF8.GetString(json));
            Assert.NotNull(canonicalizedKey);

            Assert.Null(canonicalizedKey.Alg);
            Assert.Null(canonicalizedKey.Kid);
            Assert.Null(canonicalizedKey.Use);
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

        public abstract void FromJson(string json);

        public abstract void FromJson_WithProperties(string json);

        public abstract void WriteTo();
    }
}
