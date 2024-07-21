using System;

namespace JsonWebToken.Cryptography
{
    internal static class PemParser
    {
        public static AsymmetricJwk Read(string key)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            var data = key.AsSpan().Trim();
            if (data.StartsWith(Pkcs8.PrivateKeyPrefix, StringComparison.Ordinal) && data.EndsWith(Pkcs8.PrivateKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs8.ReadPrivateKey(data);
            }
            else if (data.StartsWith(Pkcs8.PublicKeyPrefix, StringComparison.Ordinal) && data.EndsWith(Pkcs8.PublicKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs8.ReadPublicKey(data);
            }
            if (data.StartsWith(Pkcs1.PrivateRsaKeyPrefix, StringComparison.Ordinal) && data.EndsWith(Pkcs1.PrivatRsaKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs1.ReadRsaPrivateKey(data);
            }
            else if (data.StartsWith(Pkcs1.PublicRsaKeyPrefix, StringComparison.Ordinal) && data.EndsWith(Pkcs1.PublicRsaKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs1.ReadRsaPublicKey(data);
            }
#if SUPPORT_ELLIPTIC_CURVE
            if (data.StartsWith(Pkcs1.GetPrivateECKeyPrefix(), StringComparison.Ordinal) && data.EndsWith(Pkcs1.PrivateECKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs1.ReadECPrivateKey(data);
            }
#endif
            throw new ArgumentException("PEM-encoded key be contained within valid prefix and suffix.", nameof(key));
        }
    }
}
