// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using JsonWebToken.Compression;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Defines compression algorithm.</summary>
    public sealed partial class CompressionAlgorithm : IEquatable<CompressionAlgorithm>, IAlgorithm
    {
        [MagicNumber("DEF")]
        private const uint DEF = 4605252u;

        /// <summary>Deflate</summary>
        public static readonly CompressionAlgorithm Def = new CompressionAlgorithm(id: 1, "DEF", new DeflateCompressor(), new DeflateDecompressor(), true);
        
        internal static readonly CompressionAlgorithm NoCompression = new CompressionAlgorithm(id: 0, string.Empty, Compressor.Null, Decompressor.Null, false);

        /// <summary>Gets the algorithm identifier. </summary>
        public sbyte Id => _id;

        /// <summary>Gets the name of the compression algorithm.</summary>
        public JsonEncodedText Name => _utf8Name;

        /// <summary>Gets the name of the signature algorithm.</summary>
        public ReadOnlySpan<byte> Utf8Name => _utf8Name.EncodedUtf8Bytes;

        /// <summary>Gets the <see cref="Compressor"/>.</summary>
        public Compressor Compressor { get; }

        /// <summary>Gets the <see cref="Decompressor"/>.</summary>
        public Decompressor Decompressor { get; }

        /// <summary>Gets whether the compressor is enabled.</summary>
        public bool Enabled { get; }

        private readonly sbyte _id;
        private readonly JsonEncodedText _utf8Name;

        /// <summary>Initializes a new instance of the <see cref="CompressionAlgorithm"/> class.</summary>
        public CompressionAlgorithm(sbyte id, string name, Compressor compressor, Decompressor decompressor, bool enabled)
        {
            Debug.Assert(name is not null);
            Debug.Assert(compressor is not null);
            Debug.Assert(decompressor is not null);

            _id = id;
            _utf8Name = JsonEncodedText.Encode(name);
            Compressor = compressor;
            Decompressor = decompressor;
            Enabled = enabled;
        }

        /// <summary>Determines whether this instance and a specified object, which must also be a<see cref="CompressionAlgorithm"/> object, have the same value.</summary>
        public override bool Equals(object? obj)
            => Equals(obj as CompressionAlgorithm);

        /// <summary>Determines whether two specified <see cref="CompressionAlgorithm"/> objects have the same value.</summary>
        public bool Equals(CompressionAlgorithm? other) 
            => other is null ? false : Id == other.Id;

        /// <summary>Returns the hash code for this <see cref="CompressionAlgorithm"/>.</summary>
        public override int GetHashCode()
            => Id.GetHashCode();

        /// <summary>Determines whether two specified <see cref="CompressionAlgorithm"/> have the same value.</summary>
        public static bool operator ==(CompressionAlgorithm? x, CompressionAlgorithm? y)
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

        /// <summary>Determines whether two specified <see cref="CompressionAlgorithm"/> have different values.</summary>
        public static bool operator !=(CompressionAlgorithm? x, CompressionAlgorithm? y)
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

        /// <summary>Parse the current value of the <see cref="Utf8JsonReader"/> into its <see cref="CompressionAlgorithm"/> representation.</summary>
        public static bool TryParseSlow(ref Utf8JsonReader reader, [NotNullWhen(true)] out CompressionAlgorithm? algorithm)
        {
            if (reader.ValueTextEquals(Def._utf8Name.EncodedUtf8Bytes))
            {
                algorithm = Def;
                return true;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        }

        /// <summary>Parse the <see cref="ReadOnlySpan{T}"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        public static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out CompressionAlgorithm? algorithm)
        {
            if (value.Length == 3)
            {
                var zip = IntegerMarshal.ReadUInt24(value);
                if (zip == DEF)
                {
                    algorithm = Def;
                    return true;
                }
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        }

        /// <summary>Parse the <see cref="JwtElement"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        public static bool TryParse(JwtElement value, [NotNullWhen(true)] out CompressionAlgorithm? algorithm)
        {
            if (value.ValueEquals(Def.Utf8Name))
            {
                algorithm = Def;
                return true;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        }

        /// <summary>Parse the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.</summary>
        public static bool TryParse(string? value, [NotNullWhen(true)] out CompressionAlgorithm? algorithm)
        {
            if (value == "DEF")
            {
                algorithm = Def;
                return true;
            }

#if NET5_0_OR_GREATER
            Unsafe.SkipInit(out algorithm);
#else
            algorithm = default;
#endif
            return false;
        }

        /// <summary>Cast the array of <see cref="byte"/>s into its <see cref="CompressionAlgorithm"/> representation.</summary>
        public static explicit operator CompressionAlgorithm?(byte[]? value)
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

        /// <summary>Cast the <see cref="CompressionAlgorithm"/> into its <see cref="byte"/> array representation.</summary>
        public static explicit operator byte[]?(CompressionAlgorithm? value)
            => value is null ? null : value._utf8Name.EncodedUtf8Bytes.ToArray();

        /// <inheritsddoc />
        public override string ToString()
            => Name.ToString();

        internal static CompressionAlgorithm Create(string name)
            => new CompressionAlgorithm(127, name, Compressor.Null, Decompressor.Null, false);

        /// <summary>The supported <see cref="CompressionAlgorithm"/>.</summary>
        public static ReadOnlyCollection<CompressionAlgorithm> SupportedAlgorithms => Array.AsReadOnly(new[] { Def });
    }
}
