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
            if (key.StartsWith(Pkcs8.PrivateKeyPrefix) && key.EndsWith(Pkcs8.PrivateKeySuffix))
            {
                return Pkcs8.ReadPrivateKey(key);
            }
            else if (key.StartsWith(Pkcs8.PublicKeyPrefix) && key.EndsWith(Pkcs8.PublicKeySuffix))
            {
                return Pkcs8.ReadPublicKey(key);
            }
            if (key.StartsWith(Pkcs1.PrivateRsaKeyPrefix) && key.EndsWith(Pkcs1.PrivatRsaKeySuffix))
            {
                return Pkcs1.ReadRsaPrivateKey(key);
            }
            else if (key.StartsWith(Pkcs1.PublicRsaKeyPrefix) && key.EndsWith(Pkcs1.PublicRsaKeySuffix))
            {
                return Pkcs1.ReadRsaPublicKey(key);
            }
#if SUPPORT_ELLIPTIC_CURVE
            if (key.StartsWith(Pkcs1.PrivateECKeyPrefix) && key.EndsWith(Pkcs1.PrivateECKeySuffix))
            {
                return Pkcs1.ReadECPrivateKey(key);
            }
#endif
            throw new ArgumentException($"PEM-encoded key be contained within valid prefix and suffix.", nameof(key));
        }
    }
}
