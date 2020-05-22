using System;

namespace JsonWebToken.Cryptography
{
    internal class Pkcs8
    {
        internal const string PublicKeyPrefix = "-----BEGIN PUBLIC KEY-----";
        internal const string PublicKeySuffix = "-----END PUBLIC KEY-----";
        internal const string PrivateKeyPrefix = "-----BEGIN PRIVATE KEY-----";
        internal const string PrivateKeySuffix = "-----END PRIVATE KEY-----";

        public static AsymmetricJwk ReadPublicKey(string key)
        {
            string base64KeyData = key.Substring(PublicKeyPrefix.Length, key.Length - PublicKeyPrefix.Length - PublicKeySuffix.Length);
            byte[] keyData = Convert.FromBase64String(base64KeyData);

            var reader = new AsnReader(keyData);
            reader = reader.ReadSequence();
            var readerOid = reader.ReadSequence();
            var oid = readerOid.ReadOid();
            if (IsRsaKeyOid(oid))
            {
                return ReadRsaPublicKey(ref reader);
            }
#if SUPPORT_ELLIPTIC_CURVE
            else if (IsECKeyOid(oid))
            {
                var curveOid = readerOid.ReadOid();
                return ReadECPublicKey(ref reader, curveOid);
            }
#endif
            return ReadRsaPublicKey(ref reader);
        }

        // SEQUENCE
        //   INTEGER 0 version
        //   SEQUENCE
        //     OBJECT IDENTIFIER key type OID
        //     NULL or OBJECT IDENTIFIER (EC curve OID)
        public static AsymmetricJwk ReadPrivateKey(string key)
        {
            string base64KeyData = key.Substring(PrivateKeyPrefix.Length, key.Length - PrivateKeyPrefix.Length - PrivateKeySuffix.Length);
            byte[] keyData = Convert.FromBase64String(base64KeyData);

            var reader = new AsnReader(keyData);
            reader = reader.ReadSequence();
            reader.ReadInteger();
            var readerOid = reader.ReadSequence();
            var oid = readerOid.ReadOid();
            if (IsRsaKeyOid(oid))
            {
                return ReadRsaPrivateKey(ref reader);
            }
#if SUPPORT_ELLIPTIC_CURVE
            else if (IsECKeyOid(oid))
            {
                var curveOid = readerOid.ReadOid();
                return ReadECPrivateKey(ref reader, curveOid);
            }
#endif

            ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            return null!;
        }

        // SEQUENCE
        //   SEQUENCE
        //     OBJECT IDENTIFIER 1.2.840.113549.1.1.1 
        //     NULL
        //   BIT STRING
        //     SEQUENCE
        //       INTEGER
        //       INTEGER
        private static AsymmetricJwk ReadRsaPublicKey(ref AsnReader reader)
        {
            reader = reader.ReadBitString();
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

        // SEQUENCE
        //   INTEGER 0 version
        //   SEQUENCE
        //     OBJECT IDENTIFIER 1.2.840.113549.1.1.1
        //     NULL
        //   OCTET STRING
        //     SEQUENCE
        //       INTEGER 0
        //       INTEGER N
        //       INTEGER E
        //       INTEGER D
        //       INTEGER P
        //       INTEGER Q
        //       INTEGER DP
        //       INTEGER DQ
        //       INTEGER QI
        private static RsaJwk ReadRsaPrivateKey(ref AsnReader reader)
        {
            reader = reader.ReadOctetString();
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

#if SUPPORT_ELLIPTIC_CURVE
        // SEQUENCE
        //   SEQUENCE
        //     OBJECT IDENTIFIER 1.2.840.10045.2.1
        //     OBJECT IDENTIFIER EC curve OID
        //   BIT STRING public key
        private static ECJwk ReadECPublicKey(ref AsnReader reader, int[] curveOid)
        {
            var publicKey = reader.ReadBitStringBytes();
            if (publicKey.IsEmpty)
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            }

            if (publicKey[0] != 0x04)
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            }

            if ((publicKey.Length & 0x01) != 1)
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            }

            int fieldWidth = publicKey.Length / 2;

            var x = publicKey.Slice(1, fieldWidth).ToArray();
            var y = publicKey.Slice(1 + fieldWidth).ToArray();
            if (reader.Read())
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            }

            if (IsP256(curveOid))
            {
                return new ECJwk(EllipticalCurve.P256,
                    x: x,
                    y: y);
            }
            else if (IsP384(curveOid))
            {
                return new ECJwk(EllipticalCurve.P384,
                    x: x,
                    y: y);
            }
            else if (IsP521(curveOid))
            {
                return new ECJwk(EllipticalCurve.P521,
                    x: x,
                    y: y);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        // SEQUENCE
        //   INTEGER 0
        //   SEQUENCE
        //     OBJECT IDENTIFIER 1.2.840.10045.2.1 
        //     OBJECT IDENTIFIER EC curve OID
        //   OCTET STRING
        //     SEQUENCE
        //       INTEGER 1
        //       OCTET STRING private key
        //       [1]
        //         BIT STRING public key
        private static ECJwk ReadECPrivateKey(ref AsnReader reader, int[] curveOid)
        {
            reader = reader.ReadOctetString();
            reader = reader.ReadSequence();
            var version = reader.ReadInteger();
            if (version.Length != 1 || version[0] != 1)
            {
                ThrowHelper.ThrowInvalidOperationException_InvalidPem();
            }

            var privateKey = reader.ReadOctetStringBytes().ToArray();
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

            if (IsP256(curveOid))
            {
                return new ECJwk(EllipticalCurve.P256,
                    d: privateKey,
                    x: x,
                    y: y);
            }
            else if (IsP384(curveOid))
            {
                return new ECJwk(EllipticalCurve.P384,
                    d: privateKey,
                    x: x,
                    y: y);
            }
            else if (IsP521(curveOid))
            {
                return new ECJwk(EllipticalCurve.P521,
                    d: privateKey,
                    x: x,
                    y: y);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        // 1.2.840.10045.2.1
        public static bool IsECKeyOid(int[] oid)
        {
            return oid.Length == 6 &&
                           oid[0] == 1 &&
                           oid[1] == 2 &&
                           oid[2] == 840 &&
                           oid[3] == 10045 &&
                           oid[4] == 2 &&
                           oid[5] == 1;
        }


        // 1.2.840.10045.3.1.7
        public static bool IsP256(int[] oid)
        {
            return oid.Length == 7 &&
                            oid[0] == 1 &&
                            oid[1] == 2 &&
                            oid[2] == 840 &&
                            oid[3] == 10045 &&
                            oid[4] == 3 &&
                            oid[5] == 1 &&
                            oid[6] == 7;
        }

        // 1.3.132.0.34
        public static bool IsP384(int[] oid)
        {
            return oid.Length == 5 &&
                            oid[0] == 1 &&
                            oid[1] == 3 &&
                            oid[2] == 132 &&
                            oid[3] == 0 &&
                            oid[4] == 34;
        }

        // 1.3.132.0.35
        public static bool IsP521(int[] oid)
        {
            return oid.Length == 5 &&
                           oid[0] == 1 &&
                           oid[1] == 3 &&
                           oid[2] == 132 &&
                           oid[3] == 0 &&
                           oid[4] == 35;
        }
#endif
        // 1.2.840.113549.1.1.1
        public static bool IsRsaKeyOid(int[] oid)
        {
            return oid.Length == 7 &&
                            oid[0] == 1 &&
                            oid[1] == 2 &&
                            oid[2] == 840 &&
                            oid[3] == 113549 &&
                            oid[4] == 1 &&
                            oid[5] == 1 &&
                            oid[6] == 1;
        }
    }
}
