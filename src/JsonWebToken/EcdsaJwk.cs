using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class EcdsaJwk : AsymmetricJwk
    {
        public static readonly Dictionary<string, int> DefaultECDsaKeySizeInBits = new Dictionary<string, int>()
        {
            { SecurityAlgorithms.EcdsaSha256, 256 },
            { SecurityAlgorithms.EcdsaSha384, 384 },
            { SecurityAlgorithms.EcdsaSha512, 521 }
        };

        private string _x;
        private string _y;

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
            get => _x;
            set
            {
                _x = value;
                if (value != null)
                {
                    RawX = Base64UrlEncoder.DecodeBytes(value);
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
            get => _y;
            set
            {
                _y = value;
                if (value != null)
                {
                    RawY = Base64UrlEncoder.DecodeBytes(value);
                }
                else
                {
                    RawY = null;
                }
            }
        }

        [JsonIgnore]
        public byte[] RawY { get; private set; }

        public override bool HasPrivateKey => D != null;

        public override int KeySize
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

        public override int SignatureSize
        {
            get
            {
                switch (Crv)
                {
                    case JsonWebKeyECTypes.P256:
                        return 64;
                    case JsonWebKeyECTypes.P384:
                        return 96;
                    case JsonWebKeyECTypes.P521:
                        return 132;
                    default:
                        throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedCurve, Crv));
                }

                throw new InvalidOperationException();
            }
        }

        public ECDsaCng CreateECDsa(string algorithm, bool usePrivateKey)
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

            if (!ValidateECDSAKeySize(KeySize, algorithm))
            {
                throw new ArgumentOutOfRangeException(nameof(KeySize), ErrorMessages.FormatInvariant(ErrorMessages.InvalidEcdsaKeySize, Kid, DefaultECDsaKeySizeInBits[algorithm], KeySize));
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
            if (DefaultECDsaKeySizeInBits.ContainsKey(algorithm) && keySize == DefaultECDsaKeySizeInBits[algorithm])
            {
                return true;
            }

            return false;
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
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha512:
                    return true;
            }

            return false;
        }

        public override SignatureProvider CreateSignatureProvider(string algorithm, bool willCreateSignatures)
        {
            if (IsSupportedAlgorithm(algorithm))
            {
                return new EcdsaSignatureProvider(this, algorithm, willCreateSignatures);
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
    }
}
