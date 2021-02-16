// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines signature algorithm.</summary>
    public sealed partial class SignatureAlgorithm : IEquatable<SignatureAlgorithm>, IAlgorithm
    {
        private const uint _S256 = 909455955u;
        private const uint _S384 = 876098387u;
        private const uint _S512 = 842085715u;
        private const uint _none = 1701736302u;
        private const ulong _ES256X = 96989843968837ul;

#if DEBUG
#pragma warning disable CS8618
        static SignatureAlgorithm()
        {
            Utf8.AssertMagicNumber(_S256, "S256");
            Utf8.AssertMagicNumber(_S384, "S384");
            Utf8.AssertMagicNumber(_S512, "S512");
            Utf8.AssertMagicNumber(_none, "none");
            Utf8.AssertMagicNumber(_ES256X, "ES256X");
        }
#pragma warning restore CS8618 
#endif

        /// <summary>'none'</summary>
        public static readonly SignatureAlgorithm None = new SignatureAlgorithm(id: AlgorithmId.None, "none", AlgorithmCategory.None, requiredKeySizeInBits: 0, new HashAlgorithmName());

        /// <summary>'HS256'</summary>
        public static readonly SignatureAlgorithm HS256 = new SignatureAlgorithm(id: AlgorithmId.HS256, "HS256", AlgorithmCategory.Hmac, requiredKeySizeInBits: 128/*?*/, HashAlgorithmName.SHA256);

        /// <summary>'HS384'</summary>
        public static readonly SignatureAlgorithm HS384 = new SignatureAlgorithm(id: AlgorithmId.HS384, "HS384", AlgorithmCategory.Hmac, requiredKeySizeInBits: 192/*?*/, HashAlgorithmName.SHA384);

        /// <summary>'HS512'</summary>
        public static readonly SignatureAlgorithm HS512 = new SignatureAlgorithm(id: AlgorithmId.HS512, "HS512", AlgorithmCategory.Hmac, requiredKeySizeInBits: 256/*?*/, HashAlgorithmName.SHA512);

        /// <summary>'RS256'</summary>
        public static readonly SignatureAlgorithm RS256 = new SignatureAlgorithm(id: AlgorithmId.RS256, "RS256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA256);

        /// <summary>'RS384'</summary>
        public static readonly SignatureAlgorithm RS384 = new SignatureAlgorithm(id: AlgorithmId.RS384, "RS384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA384);

        /// <summary>'RS512'</summary>
        public static readonly SignatureAlgorithm RS512 = new SignatureAlgorithm(id: AlgorithmId.RS512, "RS512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048/*?*/, HashAlgorithmName.SHA512);

        /// <summary>'ES256X'</summary>
        public static readonly SignatureAlgorithm ES256X = new SignatureAlgorithm(id: AlgorithmId.ES256X, "ES256X", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 256, HashAlgorithmName.SHA256);

        /// <summary>'ES256'</summary>
        public static readonly SignatureAlgorithm ES256 = new SignatureAlgorithm(id: AlgorithmId.ES256, "ES256", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 256, HashAlgorithmName.SHA256);

        /// <summary>'ES384'</summary>
        public static readonly SignatureAlgorithm ES384 = new SignatureAlgorithm(id: AlgorithmId.ES384, "ES384", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 384, HashAlgorithmName.SHA384);

        /// <summary>'ES512'</summary>
        public static readonly SignatureAlgorithm ES512 = new SignatureAlgorithm(id: AlgorithmId.ES512, "ES512", AlgorithmCategory.EllipticCurve, requiredKeySizeInBits: 521, HashAlgorithmName.SHA512);

        /// <summary>'PS256'</summary>
        public static readonly SignatureAlgorithm PS256 = new SignatureAlgorithm(id: AlgorithmId.PS256, "PS256", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA256);

        /// <summary>'PS384'</summary>
        public static readonly SignatureAlgorithm PS384 = new SignatureAlgorithm(id: AlgorithmId.PS384, "PS384", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA384);

        /// <summary>'PS512'</summary>
        public static readonly SignatureAlgorithm PS512 = new SignatureAlgorithm(id: AlgorithmId.PS512, "PS512", AlgorithmCategory.Rsa, requiredKeySizeInBits: 2048, HashAlgorithmName.SHA512);

        private readonly AlgorithmId _id;
        private readonly JsonEncodedText _name;
        private readonly AlgorithmCategory _category;
        private readonly ushort _requiredKeySizeInBits;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly Sha2 _sha;

        private static readonly SignatureAlgorithm[] _algorithms = new[]
        {
            HS256,
            ES256,
            RS256,
            PS256,
            HS512,
            ES256X,
            ES512,
            RS512,
            PS512,
            HS384,
            ES384,
            RS384,
            PS384,
            None
        };

        /// <summary>Gets the algorithm identifier. </summary>
        public AlgorithmId Id => _id;

        /// <summary>Gets the name of the signature algorithm.</summary>
        public JsonEncodedText Name => _name;

        /// <summary>Gets the name of the signature algorithm.</summary>
        public ReadOnlySpan<byte> Utf8Name => _name.EncodedUtf8Bytes;

        /// <summary>Gets the algorithm category.</summary>
        public AlgorithmCategory Category => _category;

        /// <summary>Gets the required key size, in bits.</summary>
        public ushort RequiredKeySizeInBits => _requiredKeySizeInBits;

        /// <summary>Gets the hash algorithm. </summary>
        public HashAlgorithmName HashAlgorithm => _hashAlgorithm;

        /// <summary>Gets the <see cref="Sha2"/> algorithm. </summary>
        public Sha2 Sha => _sha;

        /// <summary>The supported <see cref="SignatureAlgorithm"/>.</summary>
        public static ReadOnlyCollection<SignatureAlgorithm> SupportedAlgorithms => Array.AsReadOnly(_algorithms);

        /// <summary>Initializes a new instance of <see cref="SignatureAlgorithm"/>. </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="category"></param>
        /// <param name="requiredKeySizeInBits"></param>
        /// <param name="hashAlgorithm"></param>
        public SignatureAlgorithm(AlgorithmId id, string name, AlgorithmCategory category, ushort requiredKeySizeInBits, HashAlgorithmName hashAlgorithm)
        {
            _id = id;
            _name = JsonEncodedText.Encode(name);
            _category = category;
            _requiredKeySizeInBits = requiredKeySizeInBits;
            _hashAlgorithm = hashAlgorithm;
            _sha = hashAlgorithm.Name switch
            {
                "SHA256" => Sha256.Shared,
                "SHA384" => Sha384.Shared,
                "SHA512" => Sha512.Shared,
                _ => ShaNull.Shared
            };
        }

        /// <summary>Determines whether this instance and a specified object, which must also be a<see cref="SignatureAlgorithm"/> object, have the same value.</summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object? obj)
        {
            return Equals(obj as SignatureAlgorithm);
        }

        /// <summary>Determines whether two specified <see cref="SignatureAlgorithm"/> objects have the same value.</summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(SignatureAlgorithm? other)
            => other is null ? false : _id == other._id;

        /// <summary>Returns the hash code for this <see cref="SignatureAlgorithm"/>.</summary>
        /// <returns></returns>
        public override int GetHashCode()
            => _id.GetHashCode();

        /// <summary>Determines whether two specified <see cref="SignatureAlgorithm"/> have the same value.</summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator ==(SignatureAlgorithm? x, SignatureAlgorithm? y)
        {
            // Fast path: should be singletons
            if (ReferenceEquals(x, y))
            {
                return true;
            }

            if (x is null)
            {
                return false;
            }

            return x.Equals(y);
        }

        /// <summary>Determines whether two specified <see cref="SignatureAlgorithm"/> have different values.</summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator !=(SignatureAlgorithm? x, SignatureAlgorithm? y)
        {
            // Fast path: should be singletons
            if (ReferenceEquals(x, y))
            {
                return false;
            }

            if (x is null)
            {
                return true;
            }

            return !x.Equals(y);
        }

        /// <summary>Cast the <see cref="SignatureAlgorithm"/> into its <see cref="string"/> representation.</summary>
        /// <param name="value"></param>
        public static explicit operator string?(SignatureAlgorithm? value)
            => value?.Name.ToString();

        /// <summary>Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        public static explicit operator SignatureAlgorithm?(string? value)
        {
            if (value is null)
            {
                return null;
            }

            if (!TryParse(Utf8.GetBytes(value), out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(value);
            }

            return algorithm;
        }

        /// <summary>Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        public static explicit operator SignatureAlgorithm?(byte[]? value)
        {
            if (value is null)
            {
                return null;
            }

            if (!TryParse(value, out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(Utf8.GetString(value));
            }

            return algorithm;
        }

        /// <summary>Reads the current value of the <paramref name="reader"/> and converts into its <see cref="SignatureAlgorithm"/> representation.</summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParseSlow(ref Utf8JsonReader reader, [NotNullWhen(true)] out SignatureAlgorithm? algorithm)
        {
            for (int i = 0; i < _algorithms.Length; i++)
            {
                if (reader.ValueTextEquals(_algorithms[i]._name.EncodedUtf8Bytes))
                {
                    algorithm = _algorithms[i];
                    return true;
                }
            }

            algorithm = null;
            return false;
        }

        /// <summary>Parses the <see cref="ReadOnlySpan{T}"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out SignatureAlgorithm? algorithm)
        {
            if (value.Length == 5)
            {
                var first = IntegerMarshal.ReadUInt8(value);
                switch (IntegerMarshal.ReadUInt32(value, 1))
                {
                    case _S256 when first == (byte)'H':
                        algorithm = HS256;
                        goto Found;
                    case _S256 when first == (byte)'R':
                        algorithm = RS256;
                        goto Found;
                    case _S256 when first == (byte)'E':
                        algorithm = ES256;
                        goto Found;
                    case _S256 when first == (byte)'P':
                        algorithm = PS256;
                        goto Found;
                    case _S384 when first == (byte)'H':
                        algorithm = HS384;
                        goto Found;
                    case _S384 when first == (byte)'R':
                        algorithm = RS384;
                        goto Found;
                    case _S384 when first == (byte)'E':
                        algorithm = ES384;
                        goto Found;
                    case _S384 when first == (byte)'P':
                        algorithm = PS384;
                        goto Found;
                    case _S512 when first == (byte)'H':
                        algorithm = HS512;
                        goto Found;
                    case _S512 when first == (byte)'R':
                        algorithm = RS512;
                        goto Found;
                    case _S512 when first == (byte)'E':
                        algorithm = ES512;
                        goto Found;
                    case _S512 when first == (byte)'P':
                        algorithm = PS512;
                        goto Found;
                }
            }
            else if (value.Length == 4 && IntegerMarshal.ReadUInt32(value) == _none)
            {
                algorithm = None;
                goto Found;
            }
            else if (value.Length == 6 && IntegerMarshal.ReadUInt48(value) == _ES256X)
            {
                algorithm = ES256X;
                goto Found;
            }

            algorithm = null;
            return false;
        Found:
            return true;
        }

        /// <summary>Parses the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(string? value, [NotNullWhen(true)] out SignatureAlgorithm? algorithm)
        {
            switch (value)
            {
                case "HS256":
                    algorithm = HS256;
                    goto Found;
                case "RS256":
                    algorithm = RS256;
                    goto Found;
                case "ES256":
                    algorithm = ES256;
                    goto Found;
                case "PS256":
                    algorithm = PS256;
                    goto Found;
                case "HS384":
                    algorithm = HS384;
                    goto Found;
                case "RS384":
                    algorithm = RS384;
                    goto Found;
                case "ES384":
                    algorithm = ES384;
                    goto Found;
                case "PS384":
                    algorithm = PS384;
                    goto Found;
                case "HS512":
                    algorithm = HS512;
                    goto Found;
                case "RS512":
                    algorithm = RS512;
                    goto Found;
                case "ES512":
                    algorithm = ES512;
                    goto Found;
                case "PS512":
                    algorithm = PS512;
                    goto Found;
                case "none":
                    algorithm = None;
                    goto Found;
                case "ES256X":
                    algorithm = ES256X;
                    goto Found;
            }

            algorithm = null;
            return false;
        Found:
            return true;
        }

        /// <summary>Parses the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(JsonElement value, [NotNullWhen(true)] out SignatureAlgorithm? algorithm)
        {
            if (value.ValueEquals(HS256._name.EncodedUtf8Bytes))
            {
                algorithm = HS256;
                goto Found;
            }
            else if (value.ValueEquals(RS256._name.EncodedUtf8Bytes))
            {
                algorithm = RS256;
                goto Found;
            }
            else if (value.ValueEquals(ES256._name.EncodedUtf8Bytes))
            {
                algorithm = ES256;
                goto Found;
            }
            else if (value.ValueEquals(PS256._name.EncodedUtf8Bytes))
            {
                algorithm = PS256;
                goto Found;
            }
            else if (value.ValueEquals(HS512._name.EncodedUtf8Bytes))
            {
                algorithm = HS512;
                goto Found;
            }
            else if (value.ValueEquals(RS512._name.EncodedUtf8Bytes))
            {
                algorithm = RS512;
                goto Found;
            }
            else if (value.ValueEquals(ES512._name.EncodedUtf8Bytes))
            {
                algorithm = ES512;
                goto Found;
            }
            else if (value.ValueEquals(PS512._name.EncodedUtf8Bytes))
            {
                algorithm = PS512;
                goto Found;
            }
            else if (value.ValueEquals(HS384._name.EncodedUtf8Bytes))
            {
                algorithm = HS384;
                goto Found;
            }
            else if (value.ValueEquals(RS384._name.EncodedUtf8Bytes))
            {
                algorithm = RS384;
                goto Found;
            }
            else if (value.ValueEquals(ES384._name.EncodedUtf8Bytes))
            {
                algorithm = ES384;
                goto Found;
            }
            else if (value.ValueEquals(PS384._name.EncodedUtf8Bytes))
            {
                algorithm = PS384;
                goto Found;
            }
            else if (value.ValueEquals(ES256X._name.EncodedUtf8Bytes))
            {
                algorithm = ES256X;
                goto Found;
            }
            else if (value.ValueEquals(None._name.EncodedUtf8Bytes))
            {
                algorithm = None;
                goto Found;
            }

            algorithm = null;
            return false;
        Found:
            return true;
        }

        /// <summary>Parse the current value of the <see cref="Utf8JsonReader"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(ref Utf8JsonReader reader, [NotNullWhen(true)] out SignatureAlgorithm? algorithm)
        {
            var value = reader.ValueSpan;
            if (TryParse(value, out algorithm))
            {
                return true;
            }

            return TryParseSlow(ref reader, out algorithm);
        }

        /// <inheritsddoc />
        public override string ToString()
            => Name.ToString();

        internal static SignatureAlgorithm Create(string name)
            => new SignatureAlgorithm(AlgorithmId.Undefined, name, AlgorithmCategory.None, 0, new HashAlgorithmName());
    }
}
