using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class EcdsaJwk : AsymmetricJwk
    {
        private readonly ConcurrentDictionary<string, EcdsaSignatureProvider> _signatureProviders = new ConcurrentDictionary<string, EcdsaSignatureProvider>();
        private readonly ConcurrentDictionary<string, EcdsaSignatureProvider> _signatureValidationProviders = new ConcurrentDictionary<string, EcdsaSignatureProvider>();

        public static readonly Dictionary<string, int> DefaultECDsaKeySizeInBits = new Dictionary<string, int>()
        {
            { SignatureAlgorithms.EcdsaSha256, 256 },
            { SignatureAlgorithms.EcdsaSha384, 384 },
            { SignatureAlgorithms.EcdsaSha512, 521 }
        };

        private string _x;
        private string _y;

        public EcdsaJwk(ECParameters parameters)
            : this()
        {
            parameters.Validate();

            RawD = parameters.D;
            RawX = parameters.Q.X;
            RawY = parameters.Q.Y;
            switch (parameters.Curve.Oid.FriendlyName)
            {
                case "nistP256":
                    Crv = JsonWebKeyECTypes.P256;
                    break;
                case "nistP384":
                    Crv = JsonWebKeyECTypes.P384;
                    break;
                case "nistP521":
                    Crv = JsonWebKeyECTypes.P521;
                    break;
                default:
                    throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedCurve, parameters.Curve.Oid.FriendlyName));
            }
        }

        private EcdsaJwk(string crv, byte[] d, byte[] x, byte[] y)
        {
            Crv = crv;
            RawD = CloneArray(d);
            RawX = CloneArray(x);
            RawY = CloneArray(y);
        }

        public EcdsaJwk()
        {
            Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve;
        }

        /// <summary>
        /// Gets or sets the 'crv' (Curve).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Crv, Required = Required.Default)]
        public string Crv { get; set; }

        /// <summary>
        /// Gets or sets the 'x' (X Coordinate).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X, Required = Required.Default)]
        public string X
        {
            get
            {
                if (_x == null)
                {
                    if (RawX != null && RawX.Length != 0)
                    {
                        _x = Base64Url.Encode(RawX);
                    }
                }

                return _x;
            }
            set
            {
                _x = value;
                if (value != null)
                {
                    RawX = Base64Url.Base64UrlDecode(value);
                }
                else
                {
                    RawX = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawX { get; private set; }

        /// <summary>
        /// Gets or sets the 'y' (Y Coordinate).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Y, Required = Required.Default)]
        public string Y
        {
            get
            {
                if (_y == null)
                {
                    if (RawY != null && RawY.Length != 0)
                    {
                        _y = Base64Url.Encode(RawY);
                    }
                }

                return _y;
            }
            set
            {
                _y = value;
                if (value != null)
                {
                    RawY = Base64Url.Base64UrlDecode(value);
                }
                else
                {
                    RawY = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawY { get; private set; }

        public override bool HasPrivateKey => RawD != null;

        public override int KeySizeInBits
        {
            get
            {
                switch (Crv)
                {
                    case JsonWebKeyECTypes.P256:
                        return 256;
                    case JsonWebKeyECTypes.P384:
                        return 384;
                    case JsonWebKeyECTypes.P521:
                        return 521;
                    default:
                        throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedCurve, Crv));
                }
            }
        }

        public ECDsa CreateECDsa(string algorithm, bool usePrivateKey)
        {
            if (Crv == null)
            {
                throw new ArgumentNullException(nameof(Crv));
            }

            if (X == null)
            {
                throw new ArgumentNullException(nameof(X));
            }

            if (Y == null)
            {
                throw new ArgumentNullException(nameof(Y));
            }

            if (!ValidateECDSAKeySize(KeySizeInBits, algorithm))
            {
                throw new ArgumentOutOfRangeException(nameof(KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.InvalidEcdsaKeySize, Kid, DefaultECDsaKeySizeInBits[algorithm], KeySizeInBits));
            }

            GCHandle keyBlobHandle = new GCHandle();
            try
            {
                uint dwMagic = GetMagicValue(usePrivateKey);
                uint cbKey = GetKeyByteCount();
                byte[] keyBlob;
                if (usePrivateKey)
                {
                    keyBlob = new byte[3 * cbKey + 2 * Marshal.SizeOf<uint>()];
                }
                else
                {
                    keyBlob = new byte[2 * cbKey + 2 * Marshal.SizeOf<uint>()];
                }

                keyBlobHandle = GCHandle.Alloc(keyBlob, GCHandleType.Pinned);
                IntPtr keyBlobPtr = keyBlobHandle.AddrOfPinnedObject();
                byte[] x = RawX;

                if (x.Length > cbKey)
                {
                    throw new ArgumentOutOfRangeException(nameof(x.Length), ErrorMessages.FormatInvariant(ErrorMessages.InvalidSize, nameof(X), cbKey, RawX.Length));
                }

                byte[] y = RawY;
                if (y.Length > cbKey)
                {
                    throw new ArgumentOutOfRangeException(nameof(y.Length), ErrorMessages.FormatInvariant(ErrorMessages.InvalidSize, nameof(Y), cbKey, RawY.Length));
                }

                Marshal.WriteInt64(keyBlobPtr, 0, dwMagic);
                Marshal.WriteInt64(keyBlobPtr, 4, cbKey);

                int index = 8;
                foreach (byte b in x)
                {
                    Marshal.WriteByte(keyBlobPtr, index++, b);
                }

                foreach (byte b in y)
                {
                    Marshal.WriteByte(keyBlobPtr, index++, b);
                }

                if (usePrivateKey)
                {
                    if (D == null)
                    {
                        throw new ArgumentNullException(nameof(D));
                    }

                    byte[] d = RawD;
                    if (d.Length > cbKey)
                    {
                        throw new ArgumentOutOfRangeException(nameof(d.Length), ErrorMessages.FormatInvariant(ErrorMessages.InvalidSize, nameof(D), cbKey, RawD.Length));
                    }

                    foreach (byte b in d)
                    {
                        Marshal.WriteByte(keyBlobPtr, index++, b);
                    }

                    Marshal.Copy(keyBlobPtr, keyBlob, 0, keyBlob.Length);
                    using (CngKey cngKey = CngKey.Import(keyBlob, CngKeyBlobFormat.EccPrivateBlob))
                    {
                        if (ValidateECDSAKeySize(cngKey.KeySize, algorithm))
                        {
                            return new ECDsaCng(cngKey);
                        }

                        throw new ArgumentOutOfRangeException(nameof(cngKey.KeySize), ErrorMessages.FormatInvariant(ErrorMessages.InvalidEcdsaKeySize, Kid, DefaultECDsaKeySizeInBits[algorithm], cngKey.KeySize));
                    }
                }
                else
                {
                    Marshal.Copy(keyBlobPtr, keyBlob, 0, keyBlob.Length);
                    using (CngKey cngKey = CngKey.Import(keyBlob, CngKeyBlobFormat.EccPublicBlob))
                    {
                        if (ValidateECDSAKeySize(cngKey.KeySize, algorithm))
                        {
                            return new ECDsaCng(cngKey);
                        }

                        throw new ArgumentOutOfRangeException(nameof(cngKey.KeySize), ErrorMessages.FormatInvariant(ErrorMessages.InvalidEcdsaKeySize, Kid, DefaultECDsaKeySizeInBits[algorithm], cngKey.KeySize));
                    }
                }
            }
            finally
            {
                if (keyBlobHandle != null)
                {
                    keyBlobHandle.Free();
                }
            }
        }

        private static bool ValidateECDSAKeySize(int keySize, string algorithm)
        {
            return DefaultECDsaKeySizeInBits.TryGetValue(algorithm, out var value) && value == keySize;
        }

        private uint GetKeyByteCount()
        {
            uint keyByteCount;
            switch (Crv)
            {
                case JsonWebKeyECTypes.P256:
                    keyByteCount = 32;
                    break;
                case JsonWebKeyECTypes.P384:
                    keyByteCount = 48;
                    break;
                case JsonWebKeyECTypes.P521:
                    keyByteCount = 66;
                    break;
                default:
                    throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedCurve, Crv));
            }

            return keyByteCount;
        }

        private uint GetMagicValue(bool willCreateSignatures)
        {
            KeyBlobMagicNumber magicNumber;
            switch (Crv)
            {
                case JsonWebKeyECTypes.P256:
                    if (willCreateSignatures)
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
                    else
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
                    break;
                case JsonWebKeyECTypes.P384:
                    if (willCreateSignatures)
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
                    else
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
                    break;
                case JsonWebKeyECTypes.P521:
                    if (willCreateSignatures)
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
                    else
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
                    break;
                default:
                    throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedCurve, Crv));
            }

            return (uint)magicNumber;
        }


        public override bool IsSupportedAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SignatureAlgorithms.EcdsaSha256:
                case SignatureAlgorithms.EcdsaSha384:
                case SignatureAlgorithms.EcdsaSha512:
                    return true;
            }

            return false;
        }

        public override SignatureProvider CreateSignatureProvider(string algorithm, bool willCreateSignatures)
        {
            if (algorithm == null)
            {
                return null;
            }

            var signatureProviders = willCreateSignatures ? _signatureProviders : _signatureValidationProviders;
            if (signatureProviders.TryGetValue(algorithm, out var cachedProvider))
            {
                return cachedProvider;
            }

            if (IsSupportedAlgorithm(algorithm))
            {
                var provider = new EcdsaSignatureProvider(this, algorithm, willCreateSignatures);
                signatureProviders.TryAdd(algorithm, provider);
                return provider;
            }

            return null;
        }

        public override KeyWrapProvider CreateKeyWrapProvider(string algorithm)
        {
            return null;
        }

        private enum KeyBlobMagicNumber : uint
        {
            BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345,
            BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345,
            BCRYPT_ECDSA_PUBLIC_P521_MAGIC = 0x35534345,
            BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345,
            BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345,
            BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 0x36534345,
        }

        public static EcdsaJwk GenerateKey(string curveId, bool withPrivateKey)
        {
            if (string.IsNullOrEmpty(curveId))
            {
                throw new ArgumentNullException(nameof(curveId));
            }

            ECCurve curve;
            switch (curveId)
            {
                case JsonWebKeyECTypes.P256:
                    curve = ECCurve.NamedCurves.nistP256;
                    break;
                case JsonWebKeyECTypes.P384:
                    curve = ECCurve.NamedCurves.nistP384;
                    break;
                case JsonWebKeyECTypes.P521:
                    curve = ECCurve.NamedCurves.nistP521;
                    break;
                default:
                    throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedCurve, curveId));
            }

            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.GenerateKey(curve);
                var parameters = ecdsa.ExportParameters(withPrivateKey);
                return FromParameters(parameters);
            }
        }

        public override JsonWebKey ExcludeOptionalMembers()
        {
            return new EcdsaJwk(Crv, RawD, RawX, RawY);
        }

        /// <summary>
        /// Returns a new instance of <see cref="EcdsaJwk"/>.
        /// </summary>
        /// <param name="parameters">A <see cref="byte"/> that contains the key parameters.</param>
        public static EcdsaJwk FromParameters(ECParameters parameters, bool computeThumbprint = false)
        {
            var key = new EcdsaJwk(parameters);
            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint(false);
            }

            return key;
        }
    }
}
