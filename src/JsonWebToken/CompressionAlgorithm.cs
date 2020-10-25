// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines compression algorithm.
    /// </summary>
    public sealed class CompressionAlgorithm : IEquatable<CompressionAlgorithm>, IAlgorithm
    {
        private const uint DEF = 4605252u;

        /// <summary>
        /// Deflate
        /// </summary>
        public static readonly CompressionAlgorithm Deflate = new CompressionAlgorithm(id: 1, "DEF", new DeflateCompressor());

        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public sbyte Id => _id;

        /// <summary>
        /// Gets the name of the compression algorithm.
        /// </summary>
        public string Name => Utf8.GetString(_utf8Name);

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        public ReadOnlySpan<byte> Utf8Name => _utf8Name;

        /// <summary>
        /// Gets the <see cref="Compressor"/>.
        /// </summary>
        public Compressor Compressor { get; }

        private readonly sbyte _id;
        private readonly byte[] _utf8Name;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompressionAlgorithm"/> class.
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="compressor"></param>
        public CompressionAlgorithm(sbyte id, string name, Compressor compressor)
        {
            if (name is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.name);
            }

            if (compressor is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.compressor);
            }

            _id = id;
            _utf8Name = Utf8.GetBytes(name);
            Compressor = compressor;
        }

        /// <summary>
        /// Determines whether this instance and a specified object, which must also be a
        /// <see cref="CompressionAlgorithm"/> object, have the same value.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object? obj)
        {
            return Equals(obj as CompressionAlgorithm);
        }

        /// <summary>
        /// Determines whether two specified <see cref="CompressionAlgorithm"/> objects have the same value.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(CompressionAlgorithm? other)
        {
            if (other is null)
            {
                return false;
            }

            return Id == other.Id;
        }

        /// <summary>
        /// Returns the hash code for this <see cref="CompressionAlgorithm"/>.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
            => Id.GetHashCode();

        /// <summary>
        /// Determines whether two specified <see cref="CompressionAlgorithm"/> have the same value.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Determines whether two specified <see cref="CompressionAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Parse the current value of the <see cref="Utf8JsonReader"/> into its <see cref="CompressionAlgorithm"/> representation.
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="algorithm"></param>
        public static bool TryParseSlow(ref Utf8JsonReader reader, [NotNullWhen(true)] out CompressionAlgorithm? algorithm)
        {
            if (reader.ValueTextEquals(Deflate._utf8Name))
            {
                algorithm = Deflate;
                return true;
            }

            algorithm = null;
            return false;
        }

        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(ReadOnlySpan<byte> value, [NotNullWhen(true)] out CompressionAlgorithm? algorithm)
        {
            if (value.Length == 3)
            {
                var zip = IntegerMarshal.ReadUInt24(value);
                if (zip == DEF)
                {
                    algorithm = Deflate;
                    return true;
                }
            }

            algorithm = null;
            return false;
        }

        /// <summary>
        /// Cast the <see cref="JwtElement"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(JwtElement value, [NotNullWhen(true)] out CompressionAlgorithm? algorithm)
        {
            if (value.ValueEquals(Deflate.Utf8Name))
            {
                algorithm = Deflate;
                return true;
            }

            algorithm = null;
            return false;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public static bool TryParse(string? value, [NotNullWhen(true)] out CompressionAlgorithm? algorithm)
        {
            if (value == "DEF")
            {
                algorithm = Deflate;
                return true;
            }

            algorithm = null;
            return false;
        }

        /// <summary>
        /// Cast the array of <see cref="byte"/>s into its <see cref="CompressionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
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

        /// <summary>
        /// Cast the <see cref="CompressionAlgorithm"/> into its <see cref="long"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator long(CompressionAlgorithm? value)
        {
            if (value is null)
            {
                return 0;
            }

            return value.Id;
        }

        /// <summary>
        /// Cast the <see cref="CompressionAlgorithm"/> into its <see cref="byte"/> array representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator byte[]?(CompressionAlgorithm? value)
        {
            if (value is null)
            {
                return null;
            }

            return value._utf8Name;
        }

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }

        internal static CompressionAlgorithm Create(string name)
            => new CompressionAlgorithm(127, name, Compressor.Null);
    }
}
