// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETSTANDARD || NETCOREAPP 
using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JsonWebToken
{
#nullable disable
    /// <summary>
    /// Represents an Elliptic Curve JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class ECJwk : AsymmetricJwk
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="parameters"></param>
        public ECJwk(ECParameters parameters)
        {
            Initialize(parameters);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y)
            : base(d)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, string d, string x, string y)
            : base(d)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, byte[] x, byte[] y)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, string x, string y)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="alg"></param>
        public ECJwk(ECParameters parameters, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(parameters);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y, SignatureAlgorithm alg)
            : base(d, alg)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, string d, string x, string y, SignatureAlgorithm alg)
            : base(d, alg)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, byte[] x, byte[] y, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, string x, string y, SignatureAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="alg"></param>
        public ECJwk(ECParameters parameters, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(parameters);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, byte[] d, byte[] x, byte[] y, KeyManagementAlgorithm alg)
            : base(d, alg)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, string d, string x, string y, KeyManagementAlgorithm alg)
            : base(d, alg)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, byte[] x, byte[] y, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>. No private key is provided.
        /// </summary>
        public ECJwk(in EllipticalCurve crv, string x, string y, KeyManagementAlgorithm alg)
            : base(alg)
        {
            Initialize(crv, x, y);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="ECJwk"/>.
        /// </summary>
        private ECJwk()
        {
        }
#nullable enable

        private void Initialize(ECParameters parameters)
        {
            parameters.Validate();

            D = parameters.D;
            X = parameters.Q.X;
            Y = parameters.Q.Y;
            switch (parameters.Curve.Oid.FriendlyName)
            {
                case "nistP256":
                case "ECDSA_P256":
                    Crv = EllipticalCurve.P256;
                    break;
                case "nistP384":
                case "ECDSA_P384":
                    Crv = EllipticalCurve.P384;
                    break;
                case "nistP521":
                case "ECDSA_P521":
                    Crv = EllipticalCurve.P521;
                    break;
                default:
                    ThrowHelper.ThrowNotSupportedException_Curve(parameters.Curve.Oid.FriendlyName);
                    break;
            }
        }

        private void Initialize(EllipticalCurve crv, string x, string y)
        {
            if (x == null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if (y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            Crv = crv;
            X = Base64Url.Decode(x);
            Y = Base64Url.Decode(y);
        }

        private void Initialize(EllipticalCurve crv, byte[] x, byte[] y)
        {
            if (x is null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if (y is null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            Crv = crv;
            X = x;
            Y = y;
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> Kty => JwkTypeNames.EllipticCurve;

        /// <summary>
        /// Gets or sets the 'crv' (Curve).
        /// </summary>
        public EllipticalCurve Crv { get; private set; }

        /// <summary>
        /// Gets or sets the 'x' (X Coordinate).
        /// </summary>
        public byte[] X { get; private set; }

        /// <summary>
        /// Gets or sets the 'y' (Y Coordinate).
        /// </summary>
        public byte[] Y { get; private set; }

        /// <inheritdoc />
        public override bool HasPrivateKey => D != null;

        /// <inheritdoc />
        public override int KeySizeInBits => Crv.KeySizeInBits;

        /// <summary>
        /// Creates an <see cref="ECDsa"/> algorithm.
        /// </summary>
        public ECDsa CreateECDsa(SignatureAlgorithm algorithm, bool usePrivateKey)
        {
            int validKeySize = ValidKeySize(algorithm);
            if (KeySizeInBits != validKeySize)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_InvalidEcdsaKeySize(this, algorithm, validKeySize, KeySizeInBits);
            }

            return ECDsa.Create(ExportParameters(usePrivateKey));
        }

        private static int ValidKeySize(SignatureAlgorithm algorithm)
        {
            return algorithm.RequiredKeySizeInBits;
        }

        /// <inheritdoc />
        public override bool IsSupported(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.EllipticCurve;
        }

        /// <inheritdoc />
        public override bool IsSupported(KeyManagementAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.EllipticCurve;
        }

        /// <inheritdoc />
        public override bool IsSupported(EncryptionAlgorithm algorithm)
        {
            return false;
        }

        /// <inheritdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm)
        {
            return new EcdsaSigner(this, algorithm);
        }

        /// <inheritdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            return new EcdhKeyWrapper(this, encryptionAlgorithm, algorithm);
        }
        
        /// <inheritdoc />
        protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            return new EcdhKeyUnwrapper(this, encryptionAlgorithm, algorithm);
        }

        /// <summary>
        /// Exports the key parameters.
        /// </summary>
        public ECParameters ExportParameters() => ExportParameters(false);

        /// <summary>
        /// Exports the key parameters.
        /// </summary>
        public ECParameters ExportParameters(bool includePrivateParameters)
        {
            var parameters = new ECParameters
            {
                Q = new ECPoint
                {
                    X = X,
                    Y = Y
                },
                Curve = Crv.CurveParameters
            };
            if (includePrivateParameters)
            {
                parameters.D = D;
            }

            return parameters;
        }

        /// <summary>
        /// Generates a private <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <returns></returns>
        public static ECJwk GeneratePrivateKey(in EllipticalCurve curve) => GenerateKey(curve, true, algorithm: (SignatureAlgorithm?)null);

        /// <summary>
        /// Generates a public <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <returns></returns>
        public static ECJwk GeneratePublicKey(in EllipticalCurve curve) => GenerateKey(curve, false, algorithm: (SignatureAlgorithm?)null);

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="withPrivateKey"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey) => GenerateKey(curve, withPrivateKey, algorithm: (SignatureAlgorithm?)null);

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey, SignatureAlgorithm? algorithm)
            => GenerateKey(curve, withPrivateKey, algorithm?.Utf8Name);

        /// <summary>
        /// Generates a <see cref="ECJwk"/>.
        /// </summary>
        /// <param name="curve"></param>
        /// <param name="withPrivateKey"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey, KeyManagementAlgorithm? algorithm)
            => GenerateKey(curve, withPrivateKey, algorithm?.Utf8Name);

        private static ECJwk GenerateKey(in EllipticalCurve curve, bool withPrivateKey, byte[]? algorithm)
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.GenerateKey(curve.CurveParameters);
            var parameters = ecdsa.ExportParameters(withPrivateKey);
            return FromParameters(parameters, algorithm, false);
        }

        /// <inheritdoc />
        protected override void Canonicalize(IBufferWriter<byte> bufferWriter)
        {
            using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
            writer.WriteStartObject();
            writer.WriteString(JwkParameterNames.CrvUtf8, Crv.Name);
            writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
            writer.WriteString(JwkParameterNames.XUtf8, Base64Url.Encode(X));
            writer.WriteString(JwkParameterNames.YUtf8, Base64Url.Encode(Y));
            writer.WriteEndObject();
            writer.Flush();
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, KeyManagementAlgorithm algorithm, bool computeThumbprint)
            => FromParameters(parameters, algorithm?.Utf8Name, computeThumbprint);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, SignatureAlgorithm algorithm, bool computeThumbprint)
            => FromParameters(parameters, algorithm?.Utf8Name, computeThumbprint);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, byte[]? algorithm, bool computeThumbprint)
        {
            var key = new ECJwk(parameters);
            if (computeThumbprint)
            {
                key.Kid = Encoding.UTF8.GetString(key.ComputeThumbprint());
            }

            if (algorithm != null)
            {
                key.Alg = algorithm;
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters) => FromParameters(parameters, (byte[]?)null, false);

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        public static ECJwk FromParameters(ECParameters parameters, bool computeThumbprint) => FromParameters(parameters, (byte[]?)null, computeThumbprint);

        /// <inheritdoc />
        public override ReadOnlySpan<byte> AsSpan()
        {
#if !NETSTANDARD2_0
            using var ecdh = ECDiffieHellman.Create(ExportParameters());
            return ecdh.PublicKey.ToByteArray();
#else
            throw new NotImplementedException();
#endif
        }

        /// <summary>
        /// Returns a new instance of <see cref="ECJwk"/>.
        /// </summary>
        internal static ECJwk FromJwtObject(JwtObject jwtObject)
        {
            Debug.Assert(jwtObject.Count == 3);
            if (!jwtObject.TryGetValue(JwkParameterNames.CrvUtf8, out var crv) || crv.Value is null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            if (!jwtObject.TryGetValue(JwkParameterNames.XUtf8, out var x) || x.Value is null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            if (!jwtObject.TryGetValue(JwkParameterNames.YUtf8, out var y) || y.Value is null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            return new ECJwk(EllipticalCurve.FromString((string)crv.Value), (string)x.Value, (string)y.Value);
        }

        internal JwtObject AsJwtObject()
        {
            var jwtObject = new JwtObject();
            jwtObject.Add(new JwtProperty(JwkParameterNames.CrvUtf8, Crv.Name));
            jwtObject.Add(new JwtProperty(JwkParameterNames.XUtf8, Base64Url.Encode(X)));
            jwtObject.Add(new JwtProperty(JwkParameterNames.YUtf8, Base64Url.Encode(Y)));

            return jwtObject;
        }

        internal static Jwk FromJsonReaderFast(ref Utf8JsonReader reader)
        {
            var key = new ECJwk();
            while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                var propertyName = reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan;
                ref byte propertyNameRef = ref MemoryMarshal.GetReference(propertyName);
                reader.Read();
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        PopulateObject(ref reader);
                        break;
                    case JsonTokenType.StartArray:
                        PopulateArray(ref reader, ref propertyNameRef, propertyName.Length, key);
                        break;
                    case JsonTokenType.String:
                        switch (propertyName.Length)
                        {
                            case 1 when propertyNameRef == (byte)'x':
                                key.X = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                break;
                            case 1 when propertyNameRef == (byte)'y':
                                key.Y = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                break;
                            case 1 when propertyNameRef == (byte)'d':
                                key.D = Base64Url.Decode(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                break;

                            case 3 when (Unsafe.ReadUnaligned<uint>(ref propertyNameRef) & 0x00ffffff) == 7762531u:
                                key.Crv = EllipticalCurve.FromSpan(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan);
                                break;
                            case 3:
                                PopulateThree(ref reader, ref propertyNameRef, key);
                                break;

                            case 8:
                                PopulateEight(ref reader, ref propertyNameRef, key);
                                break;
                            default:
                                break;
                        }
                        break;
                    default:
                        break;
                }
            }

            if (!(reader.TokenType is JsonTokenType.EndObject))
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            return key;
        }

        internal static ECJwk Populate(JwtObject @object)
        {
            var key = new ECJwk();
            for (int i = 0; i < @object.Count; i++)
            {
                var property = @object[i];
                var name = property.Utf8Name;
                switch (property.Type)
                {
                    case JwtTokenType.Array:
                        key.Populate(name, (JwtArray)property.Value!);
                        break;
                    case JwtTokenType.String:
                        if (name.SequenceEqual(JwkParameterNames.CrvUtf8))
                        {
                            key.Crv = EllipticalCurve.FromString((string)property.Value!);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.XUtf8))
                        {
                            key.X = Base64Url.Decode((string)property.Value!);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.YUtf8))
                        {
                            key.Y = Base64Url.Decode((string)property.Value!);
                        }
                        else if (name.SequenceEqual(JwkParameterNames.DUtf8))
                        {
                            key.D = Base64Url.Decode((string)property.Value!);
                        }
                        else
                        {
                            key.Populate(name, (string)property.Value!);
                        }
                        break;
                    case JwtTokenType.Utf8String:
                        key.Populate(name, (byte[])property.Value!);
                        break;
                    default:
                        break;
                }
            }

            return key;
        }

        /// <inheritsdoc />
        public override void WriteTo(Utf8JsonWriter writer)
        {
            base.WriteTo(writer);
            writer.WriteString(JwkParameterNames.CrvUtf8, Crv.Name);
            writer.WriteString(JwkParameterNames.XUtf8, Base64Url.Encode(X));
            writer.WriteString(JwkParameterNames.YUtf8, Base64Url.Encode(Y));
            if (D != null)
            {
                writer.WriteString(JwkParameterNames.DUtf8, Base64Url.Encode(D));
            }
        }

        /// <inheritsdoc />
        public override bool Equals(Jwk? other)
        {
            if (!(other is ECJwk key))
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return Crv.Id == Crv.Id &&
                X.AsSpan().SequenceEqual(key.X) &&
                Y.AsSpan().SequenceEqual(key.Y);
        }

        /// <inheritsdoc />
        public override int GetHashCode()
        {
            unchecked
            {
                const int p = 16777619;

                int hash = ((int)2166136261 ^ Crv.Id) * p;

                var x = X;
                if (x.Length >= sizeof(int))
                {
                    hash = (hash ^ Unsafe.ReadUnaligned<int>(ref x[0])) * p;
                }
                else
                {
                    for (int i = 0; i < x.Length; i++)
                    {
                        hash = (hash ^ x[i]) * p;
                    }
                }

                var y = Y;
                if (y.Length >= sizeof(int))
                {
                    hash = (hash ^ Unsafe.ReadUnaligned<int>(ref y[0])) * p;
                }
                else
                {
                    for (int i = 0; i < y.Length; i++)
                    {
                        hash = (hash ^ y[i]) * p;
                    }
                }

                return hash;
            }
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            base.Dispose();
            if (D != null)
            {
                CryptographicOperations.ZeroMemory(D);

            }
        }
    }
}
#endif
