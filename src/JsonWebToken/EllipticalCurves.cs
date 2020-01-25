// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NETCOREAPP || NETSTANDARD
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Constants for JsonWebKey Elliptical Curve Types
    /// https://tools.ietf.org/html/rfc7518#section-6.2.1.1
    /// </summary>
    public readonly struct EllipticalCurve
    {
        private static readonly byte[] P256Name = new byte[] { (byte)'P', (byte)'-', (byte)'2', (byte)'5', (byte)'6' };
        private static readonly byte[] P384Name = new byte[] { (byte)'P', (byte)'-', (byte)'3', (byte)'8', (byte)'4' };
        private static readonly byte[] P521Name = new byte[] { (byte)'P', (byte)'-', (byte)'5', (byte)'2', (byte)'1' };

        /// <summary>
        /// 'P-256'.
        /// </summary>
        public static EllipticalCurve P256 => new EllipticalCurve(1, ECCurve.NamedCurves.nistP256, P256Name, 256, 64);

        /// <summary>
        /// 'P-384'.
        /// </summary>
        public static EllipticalCurve P384 => new EllipticalCurve(2, ECCurve.NamedCurves.nistP384, P384Name, 384, 96);

        /// <summary>
        /// 'P-521'.
        /// </summary>    
        public static EllipticalCurve P521 => new EllipticalCurve(3, ECCurve.NamedCurves.nistP521, P521Name, 521, 132);

        /// <summary>
        /// Initializes a new instance of the <see cref="EllipticalCurve"/> struct.
        /// </summary>
        /// <param name="id"></param>
        /// <param name="namedCurve"></param>
        /// <param name="name"></param>
        /// <param name="keySizeInBits"></param>
        /// <param name="hashSize"></param>
        public EllipticalCurve(byte id, ECCurve namedCurve, byte[] name, int keySizeInBits, int hashSize)
        {
            Id = id;
            KeySizeInBits = keySizeInBits;
            Name = name;
            CurveParameters = namedCurve;
            HashSize = hashSize;
        }

        /// <summary>
        /// The name of the curve.
        /// </summary>
        public readonly byte[] Name;

        /// <summary>
        /// The internal id of the curve.
        /// </summary>
        public readonly byte Id;

        /// <summary>
        /// The size of the key, in bits
        /// </summary>
        public readonly int KeySizeInBits;

        /// <summary>
        /// The parameters curve.
        /// </summary>
        public readonly ECCurve CurveParameters;

        /// <summary>
        /// The size of the resulting hash.
        /// </summary>
        public readonly int HashSize;

        /// <summary>
        /// Returns the <see cref="EllipticalCurve"/> corresponding to the <paramref name="crv"/>.
        /// </summary>
        /// <param name="crv"></param>
        /// <returns></returns>
        public static EllipticalCurve FromString(string crv)
        {
            switch (crv)
            {
                case "P-256":
                    return P256;
                case "P-384":
                    return P384;
                case "P-521":
                    return P521;
                default:
                    ThrowHelper.ThrowNotSupportedException_Curve(crv);
                    return default;
            }
        }

        /// <summary>
        /// Returns the <see cref="EllipticalCurve"/> corresponding to the <paramref name="crv"/>.
        /// </summary>
        /// <param name="crv"></param>
        /// <returns></returns>
        public static EllipticalCurve FromSpan(ReadOnlySpan<byte> crv)
        {
            if (crv.Length == 5 && crv[0] == (byte)'P')
            {
                var crvSuffix = Unsafe.ReadUnaligned<uint>(ref Unsafe.AsRef(crv[1]));
                if (crvSuffix == 909455917u /* -256 */ )
                {
                    return P256;
                }
                if (crvSuffix == 876098349u /* -384 */ )
                {
                    return P384;
                }
                if (crvSuffix == 825373997u /* -521 */ )
                {
                    return P521;
                }
            }

            ThrowHelper.ThrowNotSupportedException_Curve(Utf8.GetString(crv));
            return default;
        }
    }
}
#endif