using System;

namespace JsonWebToken.Cryptography
{
    internal static class PemParser
    {
        internal static ReadOnlySpan<char> BeginPrefix => new[] { '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' ' };
        internal static ReadOnlySpan<char> EndSuffix => new[] { '-', '-', '-', '-', '-', 'E', 'N', 'D', ' ' } ;

        public static AsymmetricJwk Read(string key)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            var data = key.AsSpan().Trim();
            int startOffset = data.IndexOf(BeginPrefix);
            int endOffset = data.IndexOf(EndSuffix);

            if (startOffset != -1 && endOffset != -1)
            {
                if (data.Slice(startOffset + BeginPrefix.Length, Pkcs8.PrivateKeyPrefix.Length).SequenceEqual(Pkcs8.PrivateKeyPrefix) &&
                    data.Slice(endOffset + EndSuffix.Length, Pkcs8.PrivateKeySuffix.Length).SequenceEqual(Pkcs8.PrivateKeySuffix))
                {
                    return Pkcs8.ReadPrivateKey(data.Slice(startOffset + BeginPrefix.Length + Pkcs8.PrivateKeyPrefix.Length, endOffset - startOffset - Pkcs8.PrivateKeySuffix.Length- BeginPrefix.Length));
                }
                else if (data.Slice(startOffset + BeginPrefix.Length, Pkcs8.PublicKeyPrefix.Length).SequenceEqual(Pkcs8.PublicKeyPrefix) &&
                    data.Slice(endOffset + EndSuffix.Length, Pkcs8.PublicKeySuffix.Length).SequenceEqual(Pkcs8.PublicKeySuffix))
                {
                    return Pkcs8.ReadPublicKey(data.Slice(startOffset + BeginPrefix.Length + Pkcs8.PublicKeyPrefix.Length, endOffset - startOffset - Pkcs8.PublicKeySuffix.Length - BeginPrefix.Length));
                }
                else if (data.Slice(startOffset + BeginPrefix.Length, Pkcs1.PrivateRsaKeyLabel.Length).SequenceEqual(Pkcs1.PrivateRsaKeyLabel) &&
                   data.Slice(endOffset + EndSuffix.Length, Pkcs1.PrivateRsaKeyLabel.Length).SequenceEqual(Pkcs1.PrivateRsaKeyLabel))
                {
                    return Pkcs1.ReadRsaPrivateKey(data.Slice(startOffset + BeginPrefix.Length + Pkcs1.PrivateRsaKeyLabel.Length, endOffset - startOffset - Pkcs1.PrivateRsaKeyLabel.Length - BeginPrefix.Length));
                } 
                else if (data.Slice(startOffset + BeginPrefix.Length, Pkcs1.PublicRsaKeyLabel.Length).SequenceEqual(Pkcs1.PublicRsaKeyLabel) &&
                   data.Slice(endOffset + EndSuffix.Length, Pkcs1.PublicRsaKeyLabel.Length).SequenceEqual(Pkcs1.PublicRsaKeyLabel))
                {
                    return Pkcs1.ReadRsaPublicKey(data.Slice(startOffset + BeginPrefix.Length + Pkcs1.PublicRsaKeyLabel.Length, endOffset - startOffset - Pkcs1.PublicRsaKeyLabel.Length - BeginPrefix.Length));
                }
#if SUPPORT_ELLIPTIC_CURVE
                else if (data.Slice(startOffset + BeginPrefix.Length, Pkcs1.PrivateECKeyLabel.Length).SequenceEqual(Pkcs1.PrivateECKeyLabel) &&
                   data.Slice(endOffset + EndSuffix.Length, Pkcs1.PrivateECKeyLabel.Length).SequenceEqual(Pkcs1.PrivateECKeyLabel))
                {
                    return Pkcs1.ReadECPrivateKey(data.Slice(startOffset + BeginPrefix.Length + Pkcs1.PrivateECKeyLabel.Length, endOffset - startOffset - Pkcs1.PrivateECKeyLabel.Length - BeginPrefix.Length));
                }
#endif
                else
                {
                    throw new ArgumentException($"PEM-encoded key of type {data.Slice(endOffset + EndSuffix.Length, data.Length - endOffset - EndSuffix.Length - 5).ToString()} is not supported.", nameof(key));
                }
            }


            throw new ArgumentException("PEM-encoded key must be contained within valid prefix and suffix.", nameof(key));
        }
    }
}
