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

            key = key.Trim();
            if (key.StartsWith(Pkcs8.PrivateKeyPrefix, StringComparison.Ordinal) && key.EndsWith(Pkcs8.PrivateKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs8.ReadPrivateKey(key);
            }
            else if (key.StartsWith(Pkcs8.PublicKeyPrefix, StringComparison.Ordinal) && key.EndsWith(Pkcs8.PublicKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs8.ReadPublicKey(key);
            }
            if (key.StartsWith(Pkcs1.PrivateRsaKeyPrefix, StringComparison.Ordinal) && key.EndsWith(Pkcs1.PrivatRsaKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs1.ReadRsaPrivateKey(key);
            }
            else if (key.StartsWith(Pkcs1.PublicRsaKeyPrefix, StringComparison.Ordinal) && key.EndsWith(Pkcs1.PublicRsaKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs1.ReadRsaPublicKey(key);
            }
#if SUPPORT_ELLIPTIC_CURVE
            if (key.StartsWith(Pkcs1.PrivateECKeyPrefix, StringComparison.Ordinal) && key.EndsWith(Pkcs1.PrivateECKeySuffix, StringComparison.Ordinal))
            {
                return Pkcs1.ReadECPrivateKey(key);
            }
#endif
            throw new ArgumentException("PEM-encoded key be contained within valid prefix and suffix.", nameof(key));
        }
    }
}
