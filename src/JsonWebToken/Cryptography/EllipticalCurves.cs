// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>Constants for JsonWebKey Elliptical Curve Typeshttps://tools.ietf.org/html/rfc7518#section-6.2.1.1</summary>
    public readonly struct EllipticalCurve
    {
        private const uint _256 = 909455917u;
        private const uint _384 = 876098349u;
        private const uint _521 = 825373997u;
        private const ulong ecp256k1 = 3560999532473901925ul;
        private static readonly byte[] P256Name = new byte[] { (byte)'P', (byte)'-', (byte)'2', (byte)'5', (byte)'6' };
        private static readonly byte[] P384Name = new byte[] { (byte)'P', (byte)'-', (byte)'3', (byte)'8', (byte)'4' };
        private static readonly byte[] P521Name = new byte[] { (byte)'P', (byte)'-', (byte)'5', (byte)'2', (byte)'1' };
        private static readonly byte[] Secp256k1Name = new byte[] { (byte)'s', (byte)'e', (byte)'c', (byte)'p', (byte)'2', (byte)'5', (byte)'6', (byte)'k', (byte)'1' };

        /// <summary>'P-256'.</summary>
        public static readonly EllipticalCurve P256 = new EllipticalCurve(1, ECCurve.NamedCurves.nistP256, P256Name, 256, 64, SignatureAlgorithm.ES256);

        /// <summary>'P-384'.</summary>
        public static readonly EllipticalCurve P384 = new EllipticalCurve(2, ECCurve.NamedCurves.nistP384, P384Name, 384, 96, SignatureAlgorithm.ES384);

        /// <summary>'P-521'.</summary>    
        public static readonly EllipticalCurve P521 = new EllipticalCurve(3, ECCurve.NamedCurves.nistP521, P521Name, 521, 132, SignatureAlgorithm.ES512);

        /// <summary>'secp256k1'.</summary>    
        public static readonly EllipticalCurve Secp256k1 = new EllipticalCurve(8, ECCurve.CreateFromValue("1.3.132.0.10"), Secp256k1Name, 256, 64, SignatureAlgorithm.ES256X);

        /// <summary>Initializes a new instance of the <see cref="EllipticalCurve"/> struct.</summary>
        public EllipticalCurve(byte id, ECCurve namedCurve, byte[] name, int keySizeInBits, int hashSize, SignatureAlgorithm supportedSignatureAlgorithm)
        {
            Id = id;
            KeySizeInBits = keySizeInBits;
            Name = name;
            CurveParameters = namedCurve;
            HashSize = hashSize;
            SupportedSignatureAlgorithm = supportedSignatureAlgorithm;
        }

        /// <summary>The name of the curve.</summary>
        public readonly byte[] Name;

        /// <summary>The internal id of the curve.</summary>
        public readonly byte Id;

        /// <summary>The size of the key, in bits.</summary>
        public readonly int KeySizeInBits;

        /// <summary>The parameters curve.</summary>
        public readonly ECCurve CurveParameters;

        /// <summary>The size of the resulting hash.</summary>
        public readonly int HashSize;

        /// <summary>The supported <see cref="SignatureAlgorithm"/> for this curve.</summary>
        public readonly SignatureAlgorithm SupportedSignatureAlgorithm;

        /// <summary>Returns the <see cref="EllipticalCurve"/> corresponding to the <paramref name="crv"/>.</summary>
        public static EllipticalCurve FromString(string crv)
        {

            if (!TryParse(crv, out var curve))
            {
                ThrowHelper.ThrowNotSupportedException_Curve(crv);
            }

            return curve;
        }

        /// <summary>Tries to parse a <see cref="string"/> into a <see cref="EllipticalCurve"/>.</summary>
        public static bool TryParse(string crv, out EllipticalCurve curve)
        {
            switch (crv)
            {
                case "P-256":
                    curve = P256;
                    goto Parsed;
                case "P-384":
                    curve = P384;
                    goto Parsed;
                case "P-521":
                    curve = P521;
                    goto Parsed;
                case "secp256k1":
                    curve = Secp256k1;
                    goto Parsed;
                default:
                    curve = default;
                    return false;
            }

        Parsed:
            return true;
        }



        /// <summary>
        /// Returns the <see cref="EllipticalCurve"/> corresponding to the <paramref name="crv"/>.
        /// </summary>
        /// <param name="crv"></param>
        /// <returns></returns>
        internal static EllipticalCurve FromSpan(ReadOnlySpan<byte> crv)
        {
            ref byte crvRef = ref MemoryMarshal.GetReference(crv);
            if (crv.Length == 5 && crvRef == (byte)'P')
            {
                var crvSuffix = IntegerMarshal.ReadUInt32(ref crvRef, 1);
                if (crvSuffix == _256)
                {
                    return P256;
                }
                if (crvSuffix == _384)
                {
                    return P384;
                }
                if (crvSuffix == _521)
                {
                    return P521;
                }
            }
            else if (crv.Length == 9 && crvRef == (byte)'s' && IntegerMarshal.ReadUInt64(ref crvRef, 1) == ecp256k1)
            {
                return Secp256k1;
            }

            ThrowHelper.ThrowNotSupportedException_Curve(Utf8.GetString(crv));
            return default;
        }
    }
}
#endif