// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines encryption algorithm.</summary>
    public sealed partial class EncryptionAlgorithm : IEquatable<EncryptionAlgorithm>, IAlgorithm
    {
        private const ulong _A128CBC_ = 3261523411619426625u;
        private const ulong _BC_HS256 = 3906083585088373570u;
        private const ulong _A192CBC_ = 3261523411519222081u;
        private const ulong _BC_HS384 = 3762813921454277442u;
        private const ulong _A256CBC_ = 3261523411586069057u;
        private const ulong _BC_HS512 = 3616730607564702530u;
        private const ulong _A128GCM = 21747546371273025u;
        private const ulong _A192GCM = 21747546271068481u;
        private const ulong _A256GCM = 21747546337915457u;

        /// <summary>'A128CBC-HS256'</summary>
        public static readonly EncryptionAlgorithm A128CbcHS256 = new EncryptionAlgorithm(id: AlgorithmId.AesCbc128HS256, "A128CBC-HS256", requiredKeySizeInBytes: 32, SignatureAlgorithm.HS256, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesHmac);

        /// <summary>'A192CBC-HS384'</summary>
        public static readonly EncryptionAlgorithm A192CbcHS384 = new EncryptionAlgorithm(id: AlgorithmId.AesCbc192HS384 /* Undefined in CWT */, "A192CBC-HS384", requiredKeySizeInBytes: 48, SignatureAlgorithm.HS384, requiredKeyWrappedSizeInBytes: 56, EncryptionType.AesHmac);

        /// <summary>'A256CBC-HS512'</summary>
        public static readonly EncryptionAlgorithm A256CbcHS512 = new EncryptionAlgorithm(id: AlgorithmId.AesCbc256HS512, "A256CBC-HS512", requiredKeySizeInBytes: 64, SignatureAlgorithm.HS512, requiredKeyWrappedSizeInBytes: 72, EncryptionType.AesHmac);

        /// <summary>'A128GCM'</summary>
        public static readonly EncryptionAlgorithm A128Gcm = new EncryptionAlgorithm(id: AlgorithmId.Aes128Gcm, "A128GCM", requiredKeySizeInBytes: 16, signatureAlgorithm: SignatureAlgorithm.None, requiredKeyWrappedSizeInBytes: 24, EncryptionType.AesGcm);

        /// <summary>'A192GCM'</summary>
        public static readonly EncryptionAlgorithm A192Gcm = new EncryptionAlgorithm(id: AlgorithmId.Aes192Gcm, "A192GCM", requiredKeySizeInBytes: 24, signatureAlgorithm: SignatureAlgorithm.None, requiredKeyWrappedSizeInBytes: 32, EncryptionType.AesGcm);

        /// <summary>'A256GCM'</summary>
        public static readonly EncryptionAlgorithm A256Gcm = new EncryptionAlgorithm(id: AlgorithmId.Aes256Gcm, "A256GCM", requiredKeySizeInBytes: 32, signatureAlgorithm: SignatureAlgorithm.None, requiredKeyWrappedSizeInBytes: 40, EncryptionType.AesGcm);

        private static readonly EncryptionAlgorithm[] _algorithms = new[]
        {
            A128CbcHS256,
            A192CbcHS384,
            A256CbcHS512,
            A128Gcm,
            A192Gcm,
            A256Gcm
        };

        private readonly AlgorithmId _id;
        private readonly EncryptionType _category;
        private readonly ushort _requiredKeySizeInBytes;
        private readonly ushort _keyWrappedSizeInBytes;
        private readonly SignatureAlgorithm _signatureAlgorithm;
        private readonly AuthenticatedEncryptor _encryptor;
        private readonly AuthenticatedDecryptor _decryptor;
        private readonly JsonEncodedText _utf8Name;

        /// <summary>Gets the algorithm identifier. </summary>
        public AlgorithmId Id => _id;

        /// <summary>Gets the algorithm category.</summary>
        public EncryptionType Category => _category;

        /// <summary>Gets the required key size, in bytes.</summary>
        public ushort RequiredKeySizeInBytes => _requiredKeySizeInBytes;

        /// <summary>
        /// Gets the required key size, in bits.
        /// </summary>
        public int RequiredKeySizeInBits => _requiredKeySizeInBytes << 3;

        /// <summary>Gets the wrapped key size, in bits.</summary>
        public ushort KeyWrappedSizeInBytes => _keyWrappedSizeInBytes;

        /// <summary>Gets the <see cref="SignatureAlgorithm"/>.</summary>
        public SignatureAlgorithm SignatureAlgorithm => _signatureAlgorithm;

        /// <summary>Gets the name of the encryption algorithm.</summary>
        public JsonEncodedText Name => _utf8Name;

        /// <summary>Gets the name of the signature algorithm.</summary>
        public ReadOnlySpan<byte> Utf8Name => _utf8Name.EncodedUtf8Bytes;

        /// <summary>Gets the <see cref="AuthenticatedEncryptor"/>.</summary>
        public AuthenticatedEncryptor Encryptor => _encryptor;

        /// <summary>Gets the <see cref="AuthenticatedDecryptor"/>.</summary>
        public AuthenticatedDecryptor Decryptor => _decryptor;

        /// <summary>Initializes a new instance of <see cref="EncryptionAlgorithm"/>.</summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="requiredKeySizeInBytes"></param>
        /// <param name="signatureAlgorithm"></param>
        /// <param name="requiredKeyWrappedSizeInBytes"></param>
        /// <param name="category"></param>
        public EncryptionAlgorithm(AlgorithmId id, string name, ushort requiredKeySizeInBytes, SignatureAlgorithm signatureAlgorithm, ushort requiredKeyWrappedSizeInBytes, EncryptionType category)
        {
            _id = id;
            _utf8Name = JsonEncodedText.Encode(name);
            _requiredKeySizeInBytes = requiredKeySizeInBytes;
            _signatureAlgorithm = signatureAlgorithm;
            _keyWrappedSizeInBytes = requiredKeyWrappedSizeInBytes;
            _category = category;
            _encryptor = CreateAuthenticatedEncryptor(this);
            _decryptor = CreateAuthenticatedDecryptor(this);
        }

        /// <summary>Parses the current value of the <see cref="Utf8JsonReader"/> into its <see cref="EncryptionAlgorithm"/> representation.</summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParseSlow(ref Utf8JsonReader reader, [NotNullWhen(true)] out EncryptionAlgorithm? algorithm)
        {
            var algorithms = _algorithms;
            for (int i = 0; i < algorithms.Length; i++)
            {
                if (reader.ValueTextEquals(algorithms[i]._utf8Name.EncodedUtf8Bytes))
                {
                    algorithm = algorithms[i];
                    return true;
                }
            }

            algorithm = null;
            return false;
        }

        /// <summary>Parses the <see cref="ReadOnlySpan{T}"/> into its <see cref="EncryptionAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out EncryptionAlgorithm? algorithm)
        {
            if (value.Length == 13)
            {
                switch (IntegerMarshal.ReadUInt64(value))
                {
                    case _A128CBC_ when IntegerMarshal.ReadUInt64(value, 5) == _BC_HS256:
                        algorithm = A128CbcHS256;
                        goto Found;
                    case _A192CBC_ when IntegerMarshal.ReadUInt64(value, 5) == _BC_HS384:
                        algorithm = A192CbcHS384;
                        goto Found;
                    case _A256CBC_ when IntegerMarshal.ReadUInt64(value, 5) == _BC_HS512:
                        algorithm = A256CbcHS512;
                        goto Found;
                }
            }
            else if (value.Length == 7)
            {
                switch (IntegerMarshal.ReadUInt56(value))
                {
                    case _A128GCM:
                        algorithm = A128Gcm;
                        goto Found;
                    case _A192GCM:
                        algorithm = A192Gcm;
                        goto Found;
                    case _A256GCM:
                        algorithm = A256Gcm;
                        goto Found;
                }
            }

            algorithm = null;
            return false;
        Found:
            return true;
        }

        /// <summary>Parses the <see cref="string"/> into its <see cref="EncryptionAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(string? value, [NotNullWhen(true)] out EncryptionAlgorithm? algorithm)
        {
            switch (value)
            {
                case "A128CBC-HS256":
                    algorithm = A128CbcHS256;
                    goto Found;
                case "A192CBC-HS384":
                    algorithm = A192CbcHS384;
                    goto Found;
                case "A256CBC-HS512":
                    algorithm = A256CbcHS512;
                    goto Found;

                case "A128GCM":
                    algorithm = A128Gcm;
                    goto Found;
                case "A192GCM":
                    algorithm = A192Gcm;
                    goto Found;
                case "A256GCM":
                    algorithm = A256Gcm;
                    goto Found;
            }

            algorithm = null;
            return false;
        Found:
            return true;
        }

        /// <summary>Parses the <see cref="JwtElement"/> into its <see cref="EncryptionAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(JwtElement value, [NotNullWhen(true)] out EncryptionAlgorithm? algorithm)
        {
            bool found;
            if (value.ValueEquals(A128CbcHS256._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A128CbcHS256;
                found = true;
            }
            else if (value.ValueEquals(A192CbcHS384._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A192CbcHS384;
                found = true;
            }
            else if (value.ValueEquals(A256CbcHS512._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A256CbcHS512;
                found = true;
            }
            else if (value.ValueEquals(A128Gcm._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A128Gcm;
                found = true;
            }
            else if (value.ValueEquals(A192Gcm._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A192Gcm;
                found = true;
            }
            else if (value.ValueEquals(A256Gcm._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A256Gcm;
                found = true;
            }
            else
            {
                algorithm = null;
                found = false;
            }

            return found;
        }

        /// <summary>Parses the <see cref="JsonElement"/> into its <see cref="EncryptionAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(JsonElement value, [NotNullWhen(true)] out EncryptionAlgorithm? algorithm)
        {
            bool found;
            if (value.ValueEquals(A128CbcHS256._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A128CbcHS256;
                found = true;
            }
            else if (value.ValueEquals(A192CbcHS384._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A192CbcHS384;
                found = true;
            }
            else if (value.ValueEquals(A256CbcHS512._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A256CbcHS512;
                found = true;
            }
            else if (value.ValueEquals(A128Gcm._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A128Gcm;
                found = true;
            }
            else if (value.ValueEquals(A192Gcm._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A192Gcm;
                found = true;
            }
            else if (value.ValueEquals(A256Gcm._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = A256Gcm;
                found = true;
            }
            else
            {
                algorithm = null;
                found = false;
            }

            return found;
        }

        /// <summary>Determines whether this instance and a specified object, which must also be a<see cref="EncryptionAlgorithm"/> object, have the same value.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object? obj)
            => Equals(obj as EncryptionAlgorithm);

        /// <summary>Determines whether two specified <see cref="EncryptionAlgorithm"/> objects have the same value.</summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(EncryptionAlgorithm? other)
            => other is null ? false : _id == other._id;

        /// <summary>Returns the hash code for this <see cref="EncryptionAlgorithm"/>.</summary>
        /// <returns></returns>
        public override int GetHashCode()
            => _id.GetHashCode();

        /// <summary>Determines whether two specified <see cref="EncryptionAlgorithm"/> have the same value.</summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool operator ==(EncryptionAlgorithm? x, EncryptionAlgorithm? y)
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

        /// <summary>Determines whether two specified <see cref="EncryptionAlgorithm"/> have different values.</summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool operator !=(EncryptionAlgorithm? x, EncryptionAlgorithm? y)
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

        /// <summary>Cast the <see cref="EncryptionAlgorithm"/> into its <see cref="string"/> representation.</summary>
        /// <param name="value"></param>
        public static explicit operator string?(EncryptionAlgorithm? value)
            => value?.Name.ToString();

        /// <summary>Cast the <see cref="EncryptionAlgorithm"/> into its <see cref="byte"/> array representation.</summary>
        /// <param name="value"></param>
        public static explicit operator byte[]?(EncryptionAlgorithm? value)
            => value is null ? null : value._utf8Name.EncodedUtf8Bytes.ToArray();

        /// <summary>Cast the array of <see cref="byte"/>s into its <see cref="EncryptionAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        public static explicit operator EncryptionAlgorithm?(byte[]? value)
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

        /// <summary>Cast the <see cref="string"/> into its <see cref="EncryptionAlgorithm"/> representation.</summary>
        /// <param name="value"></param>
        public static explicit operator EncryptionAlgorithm?(string? value)
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

        /// <inheritsddoc />
        public override string ToString()
            => Name.ToString();

        /// <summary>Computes a unique key for the combinaison of the <see cref="EncryptionAlgorithm"/> and the <see cref="KeyManagementAlgorithm"/>.</summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public int ComputeKey(KeyManagementAlgorithm algorithm)
            => ((ushort)_id << 16) | (ushort)algorithm.Id;

        internal static EncryptionAlgorithm Create(string name)
            => new EncryptionAlgorithm(AlgorithmId.Undefined, name, 0, SignatureAlgorithm.None, 0, EncryptionType.NotSupported);

        internal static AuthenticatedDecryptor CreateAuthenticatedDecryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category == EncryptionType.AesHmac)
            {
#if SUPPORT_SIMD
                if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
                {
                    if (encryptionAlgorithm.Id == AlgorithmId.AesCbc128HS256)
                    {
                        return new AesCbcHmacDecryptor(encryptionAlgorithm, new Aes128CbcDecryptor());
                    }
                    else if (encryptionAlgorithm.Id == AlgorithmId.AesCbc256HS512)
                    {
                        return new AesCbcHmacDecryptor(encryptionAlgorithm, new Aes256CbcDecryptor());
                    }
                    else if (encryptionAlgorithm.Id == AlgorithmId.AesCbc192HS384)
                    {
                        return new AesCbcHmacDecryptor(encryptionAlgorithm, new Aes192CbcDecryptor());
                    }
                }
                else
                {
                    return new AesCbcHmacDecryptor(encryptionAlgorithm);
                }
#else
                return new AesCbcHmacDecryptor(encryptionAlgorithm);
#endif
            }
#if SUPPORT_AESGCM
            else if (encryptionAlgorithm.Category == EncryptionType.AesGcm)
            {
                return new AesGcmDecryptor(encryptionAlgorithm);
            }
#endif
            return new NullAesDecryptor();
        }

        internal static AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category == EncryptionType.AesHmac)
            {
#if SUPPORT_SIMD
                if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
                {
                    switch (encryptionAlgorithm.Id)
                    {
                        case AlgorithmId.AesCbc128HS256:
                            return new AesCbcHmacEncryptor(encryptionAlgorithm, new Aes128CbcEncryptor());
                        case AlgorithmId.AesCbc256HS512:
                            return new AesCbcHmacEncryptor(encryptionAlgorithm, new Aes256CbcEncryptor());
                        case AlgorithmId.AesCbc192HS384:
                            return new AesCbcHmacEncryptor(encryptionAlgorithm, new Aes192CbcEncryptor());
                    }
                }
                else
                {
                    return new AesCbcHmacEncryptor(encryptionAlgorithm, new AesCbcEncryptor(encryptionAlgorithm));
                }
#else
                return new AesCbcHmacEncryptor(encryptionAlgorithm);
#endif
            }
#if SUPPORT_AESGCM
            else if (encryptionAlgorithm.Category == EncryptionType.AesGcm)
            {
                return new AesGcmEncryptor(encryptionAlgorithm);
            }
#endif

            return new NullAesEncryptor();
        }

        private sealed class NullAesEncryptor : AuthenticatedEncryptor
        {
            public override void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag, out int authenticationTagBytesWritten)
            {
                authenticationTagBytesWritten = 0;
            }

            public override int GetBase64NonceSize()
                => 0;

            public override int GetCiphertextSize(int plaintextSize)
                => 0;

            public override int GetNonceSize()
                => 0;

            public override int GetTagSize()
                => 0;
        }

        private sealed class NullAesDecryptor : AuthenticatedDecryptor
        {
            public override bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
            {
                bytesWritten = 0;
                return true;
            }
        }
    }
}
