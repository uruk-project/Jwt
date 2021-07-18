using System;
using System.Buffers;

namespace JsonWebToken.Cryptography
{
    internal static class Pkcs1
    {
        public const string PublicRsaKeyPrefix = "-----BEGIN RSA PUBLIC KEY-----";
        public const string PublicRsaKeySuffix = "-----END RSA PUBLIC KEY-----";
        public const string PrivateRsaKeyPrefix = "-----BEGIN RSA PRIVATE KEY-----";
        public const string PrivatRsaKeySuffix = "-----END RSA PRIVATE KEY-----";

#if SUPPORT_ELLIPTIC_CURVE
        public const string PrivateECKeyPrefix = "-----BEGIN EC PRIVATE KEY-----";
        public const string PrivateECKeySuffix = "-----END EC PRIVATE KEY-----";
#endif

        // SEQUENCE
        //   INTEGER N
        //   INTEGER E
        public static RsaJwk ReadRsaPublicKey(ReadOnlySpan<char> key)
        {
            var data = key.Slice(PublicRsaKeyPrefix.Length, key.Length - PublicRsaKeyPrefix.Length - PublicRsaKeySuffix.Length);
            byte[] tmpArray;
            Span<byte> keyData = tmpArray = ArrayPool<byte>.Shared.Rent(Base64.GetArraySizeRequiredToDecode(data.Length));
            try
            {
                int length = Base64.Decode(data, keyData);
                var reader = new AsnReader(keyData.Slice(0, length));

                reader = reader.ReadSequence();
                var n = reader.ReadInteger();
                var e = reader.ReadInteger();
                if (reader.Read())
                {
                    ThrowHelper.ThrowInvalidOperationException_InvalidPem();
                }

                return RsaJwk.FromByteArray(
                    n: AsnReader.TrimLeadingZeroes(n),
                    e: AsnReader.TrimLeadingZeroes(e, align: false));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tmpArray);
            }
        }

        // SEQUENCE
        //   INTEGER 0
        //   INTEGER N
        //   INTEGER E
        //   INTEGER D
        //   INTEGER P
        //   INTEGER Q
        //   INTEGER DP
        //   INTEGER DQ
        //   INTEGER QI
        public static RsaJwk ReadRsaPrivateKey(ReadOnlySpan<char> key)
        {
            var data = key.Slice(PrivateRsaKeyPrefix.Length, key.Length - PrivateRsaKeyPrefix.Length - PrivatRsaKeySuffix.Length);
            byte[] tmpArray;
            Span<byte> keyData = tmpArray = ArrayPool<byte>.Shared.Rent(Base64.GetArraySizeRequiredToDecode(data.Length));
            try
            {
                int length = Base64.Decode(data, keyData);
                var reader = new AsnReader(keyData.Slice(0, length));
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

                return RsaJwk.FromByteArray(
                    n: AsnReader.TrimLeadingZeroes(n),
                    e: AsnReader.TrimLeadingZeroes(e, align: false),
                    d: AsnReader.TrimLeadingZeroes(d),
                    p: AsnReader.TrimLeadingZeroes(p),
                    q: AsnReader.TrimLeadingZeroes(q),
                    dp: AsnReader.TrimLeadingZeroes(dp),
                    dq: AsnReader.TrimLeadingZeroes(dq),
                    qi: AsnReader.TrimLeadingZeroes(qi));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tmpArray);
            }
        }

#if SUPPORT_ELLIPTIC_CURVE
        // SEQUENCE
        //   INTEGER 1
        //   OCTET STRING private key
        //   [0]
        //     OBJECT IDENTIFIER  1.2.840.10045.3.1.7
        //   [1]
        //     BIT STRING public key
        public static ECJwk ReadECPrivateKey(ReadOnlySpan<char> key)
        {
            var data = key.Slice(PrivateECKeyPrefix.Length, key.Length - PrivateECKeyPrefix.Length - PrivateECKeySuffix.Length);
            byte[] tmpArray;
            Span<byte> keyData = tmpArray = ArrayPool<byte>.Shared.Rent(Base64.GetArraySizeRequiredToDecode(data.Length));
            try
            {
                int length = Base64.Decode(data, keyData);
                var reader = new AsnReader(keyData.Slice(0, length));

                reader = reader.ReadSequence();
                var version = reader.ReadInteger();
                if (version.Length != 1 || version[0] != 1)
                {
                    ThrowHelper.ThrowInvalidOperationException_InvalidPem();
                }

                var privateKey = reader.ReadOctetStringBytes().ToArray();
                var readerOid = reader.ReadSequence(true);
                var curveOid = readerOid.ReadOid();
                reader = reader.ReadSequence(true);
                var publicKey = reader.ReadBitStringBytes();
                if (publicKey.IsEmpty)
                {
                    ThrowHelper.ThrowInvalidOperationException_InvalidPem();
                }

                if (publicKey[0] != 0x04)
                {
                    ThrowHelper.ThrowInvalidOperationException_InvalidPem();
                }

                if (publicKey.Length != 2 * privateKey.Length + 1)
                {
                    ThrowHelper.ThrowInvalidOperationException_InvalidPem();
                }

                var x = publicKey.Slice(1, privateKey.Length).ToArray();
                var y = publicKey.Slice(1 + privateKey.Length).ToArray();
                if (reader.Read())
                {
                    ThrowHelper.ThrowInvalidOperationException_InvalidPem();
                }

                if (Pkcs8.IsP256(curveOid))
                {
                    return ECJwk.FromByteArray(EllipticalCurve.P256,
                        d: privateKey,
                        x: x,
                        y: y);
                }
                else if (Pkcs8.IsP384(curveOid))
                {
                    return ECJwk.FromByteArray(EllipticalCurve.P384,
                        d: privateKey,
                        x: x,
                        y: y);
                }
                else if (Pkcs8.IsP521(curveOid))
                {
                    return ECJwk.FromByteArray(EllipticalCurve.P521,
                        d: privateKey,
                        x: x,
                        y: y);
                }
                else
                {
                    throw new NotSupportedException();
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tmpArray);
            }
        }
#endif
    }
}