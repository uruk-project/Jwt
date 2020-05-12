using System;

namespace JsonWebToken.Cryptography
{
    internal class Pkcs1
    {
        public static RsaJwk FromPublicKey(string key)
        {
            const string PublicKeyPrefix = "-----BEGIN RSA PUBLIC KEY-----";
            const string PublicKeySuffix = "-----END RSA PUBLIC KEY-----";

            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            key = key.Trim();
            if (!key.StartsWith(PublicKeyPrefix) || !key.EndsWith(PublicKeySuffix))
            {
                throw new ArgumentException($"PEM-encoded key be contained within '{PublicKeyPrefix}' and '{PublicKeySuffix}'.", nameof(key));
            }

            string base64PrivateKey = key.Substring(PublicKeyPrefix.Length, key.Length - PublicKeyPrefix.Length - PublicKeySuffix.Length);
            byte[] pkcs8Bytes = Convert.FromBase64String(base64PrivateKey);

            var reader = new AsnReader(pkcs8Bytes);
            reader = reader.ReadSequence();
            var n = reader.ReadInteger();
            var e = reader.ReadInteger();
            if (reader.Read())
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            }

            return new RsaJwk(
                n: AsnReader.TrimLeadingZeroes(n),
                e: AsnReader.TrimLeadingZeroes(e, align: false));
        }

        public static RsaJwk FromPrivateKey(string key)
        {
            const string PrivateKeyPrefix = "-----BEGIN RSA PRIVATE KEY-----";
            const string PrivateKeySuffix = "-----END RSA PRIVATE KEY-----";

            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            key = key.Trim();
            if (!key.StartsWith(PrivateKeyPrefix) || !key.EndsWith(PrivateKeySuffix))
            {
                throw new ArgumentException($"PEM-encoded-key be contained within '{PrivateKeyPrefix}' and '{PrivateKeySuffix}'.", nameof(key));
            }

            string base64PrivateKey = key.Substring(PrivateKeyPrefix.Length, key.Length - PrivateKeyPrefix.Length - PrivateKeySuffix.Length);
            byte[] pkcs8Bytes = Convert.FromBase64String(base64PrivateKey);

            var reader = new AsnReader(pkcs8Bytes);
            reader = reader.ReadSequence();
            var version = reader.ReadInteger();
            if (version.Length != 1 || version[0] != 0)
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            }

            var n = reader.ReadInteger();
            var e = reader.ReadInteger();
            var d = reader.ReadInteger();
            var p = reader.ReadInteger();
            var q = reader.ReadInteger();
            var dp = reader.ReadInteger();
            var dq = reader.ReadInteger();
            var qi = reader.ReadInteger();
            if (reader.Read())
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            }

            return new RsaJwk(
                n: AsnReader.TrimLeadingZeroes(n),
                e: AsnReader.TrimLeadingZeroes(e, align: false),
                d: AsnReader.TrimLeadingZeroes(d),
                p: AsnReader.TrimLeadingZeroes(p),
                q: AsnReader.TrimLeadingZeroes(q),
                dp: AsnReader.TrimLeadingZeroes(dp),
                dq: AsnReader.TrimLeadingZeroes(dq),
                qi: AsnReader.TrimLeadingZeroes(qi));
        }
    }
}
