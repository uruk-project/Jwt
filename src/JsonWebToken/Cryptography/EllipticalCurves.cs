// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE
using System;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace JsonWebToken
{
    /// <summary>Elliptical Curve Types.</summary>
    public sealed class EllipticalCurve
    {
        [MagicNumber("-256")]
        private const uint _256 = 909455917u;

        [MagicNumber("-384")]
        private const uint _384 = 876098349u;

        [MagicNumber("-521")]
        private const uint _521 = 825373997u;

        [MagicNumber("ecp256k1")]
        private const ulong ecp256k1 = 3560999532473901925ul;

        /// <summary>No curve defined.</summary>
        internal static readonly EllipticalCurve Empty = new EllipticalCurve(id: 0, namedCurve: default, name: default,
            supportedSignatureAlgorithm: SignatureAlgorithm.None, keySizeInBits: 0, hashSize: 0, canonicalizeSize: 35);

        /// <summary>'P-256'.</summary>
        public static readonly EllipticalCurve P256 = new EllipticalCurve(id: 1, namedCurve: ECCurve.NamedCurves.nistP256, name: EllipticalCurveNames.P256,
            supportedSignatureAlgorithm: SignatureAlgorithm.ES256, keySizeInBits: 256, hashSize: 64, canonicalizeSize: 126);

        /// <summary>'P-384'.</summary>
        public static readonly EllipticalCurve P384 = new EllipticalCurve(id: 2, namedCurve: ECCurve.NamedCurves.nistP384, name: EllipticalCurveNames.P384,
            supportedSignatureAlgorithm: SignatureAlgorithm.ES384, keySizeInBits: 384, hashSize: 96, canonicalizeSize: 168);

        /// <summary>'P-521'.</summary>    
        public static readonly EllipticalCurve P521 = new EllipticalCurve(id: 3, namedCurve: ECCurve.NamedCurves.nistP521, name: EllipticalCurveNames.P521,
            supportedSignatureAlgorithm: SignatureAlgorithm.ES512, keySizeInBits: 521, hashSize: 132, canonicalizeSize: 216);

        /// <summary>'secp256k1'.</summary>    
        public static readonly EllipticalCurve Secp256k1 = new EllipticalCurve(id: 8, namedCurve: ECCurve.CreateFromValue("1.3.132.0.10"), name: EllipticalCurveNames.Secp256k1,
            supportedSignatureAlgorithm: SignatureAlgorithm.ES256K, keySizeInBits: 256, hashSize: 64, canonicalizeSize: 130);

        /// <summary>Initializes a new instance of the <see cref="EllipticalCurve"/> struct.</summary>
        private EllipticalCurve(byte id, ECCurve namedCurve, JsonEncodedText name, SignatureAlgorithm supportedSignatureAlgorithm, int keySizeInBits, int hashSize, int canonicalizeSize)
        {
            Id = id;
            KeySizeInBits = keySizeInBits;
            Name = name;
            CurveParameters = namedCurve;
            HashSize = hashSize;
            CanonicalizeSize = canonicalizeSize;
            SupportedSignatureAlgorithm = supportedSignatureAlgorithm;
        }

        /// <summary>The name of the curve.</summary>
        public JsonEncodedText Name { get; }

        /// <summary>The internal id of the curve.</summary>
        public byte Id { get; }

        /// <summary>The size of the key, in bits.</summary>
        public int KeySizeInBits { get; }

        /// <summary>The parameters curve.</summary>
        public ECCurve CurveParameters { get; }

        /// <summary>The size of the resulting hash.</summary>
        public int HashSize { get; }

        /// <summary>The size of the canonicalized form.</summary>
        public int CanonicalizeSize { get; }

        /// <summary>The supported <see cref="SignatureAlgorithm"/> for this curve.</summary>
        public SignatureAlgorithm SupportedSignatureAlgorithm { get; }

        /// <summary>The supported <see cref="EllipticalCurve"/>s.</summary>
        public static ReadOnlyCollection<EllipticalCurve> SupportedCurves => Array.AsReadOnly(_supportedCurves);

        private static readonly EllipticalCurve[] _supportedCurves = !RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
        ? new[]
            {
                P256,
                P384,
                P521,
                Secp256k1
            }
        // MacOS does not support other curves than secp256r1, secp384r1 and secp521r1
        : new[]
            {
                P256,
                P384,
                P521
            };

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
        public static bool TryParse(string crv, [NotNullWhen(true)] out EllipticalCurve? curve)
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
#if NET5_0_OR_GREATER
                    Unsafe.SkipInit(out curve);
#else
                    curve = default;
#endif
                    return false;
            }

        Parsed:
            return true;
        }

        /// <summary>Parses the <see cref="JsonElement"/> into its <see cref="EllipticalCurve"/> representation.</summary>
        public static bool TryParse(JsonElement value, [NotNullWhen(true)] out EllipticalCurve? curve)
        {
            if (value.ValueEquals(P256.Name.EncodedUtf8Bytes))
            {
                curve = P256;
                goto Found;
            }
            else if (value.ValueEquals(P384.Name.EncodedUtf8Bytes))
            {
                curve = P384;
                goto Found;
            }
            else if (value.ValueEquals(P521.Name.EncodedUtf8Bytes))
            {
                curve = P521;
                goto Found;
            }
            else if (value.ValueEquals(Secp256k1.Name.EncodedUtf8Bytes))
            {
                curve = Secp256k1;
                goto Found;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out curve);
#else
            curve = default;
#endif
            return false;
        Found:
            return true;
        }

        /// <summary>Returns the <see cref="EllipticalCurve"/> corresponding to the <paramref name="crv"/>.</summary>
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
            return null;
        }

        /// <summary>Gets the supported <see cref="EllipticalCurve"/> for the provided <see cref="SignatureAlgorithm"/>.</summary>
        public static bool TryGetSupportedCurve(SignatureAlgorithm algorithm,  [NotNullWhen(true)] out EllipticalCurve? curve)
        {
            for (int i = 0; i < _supportedCurves.Length; i++)
            {
                var current = _supportedCurves[i];
                if (current.SupportedSignatureAlgorithm == algorithm)
                {
                    curve = current;
                    return true;
                }
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out curve);
#else
            curve = default;
#endif
            return false;
        }

        /// <inheritdoc />
        public override string ToString()
            => Name.ToString();
    }
}
#endif