// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Defines compression algorithm.
    /// </summary>
    public sealed class CompressionAlgorithm : IEquatable<CompressionAlgorithm>, IAlgorithm
    {
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
        public string Name => Encoding.UTF8.GetString(_utf8Name);

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        public byte[] Utf8Name => _utf8Name;

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
            _utf8Name = Encoding.UTF8.GetBytes(name);
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
            if (obj is CompressionAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
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
        {
            return Id.GetHashCode();
        }

        /// <summary>
        /// Determines whether two specified <see cref="CompressionAlgorithm"/> have the same value.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator ==(CompressionAlgorithm? x, CompressionAlgorithm? y)
        {
            if (x is null && y is null)
            {
                return true;
            }

            if (x is null)
            {
                return false;
            }

            if (y is null)
            {
                return false;
            }

            return x.Id == y.Id;
        }

        /// <summary>
        /// Determines whether two specified <see cref="CompressionAlgorithm"/> have different values.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public static bool operator !=(CompressionAlgorithm? x, CompressionAlgorithm? y)
        {
            if (x is null && y is null)
            {
                return false;
            }

            if (x is null)
            {
                return true;
            }

            if (y is null)
            {
                return true;
            }

            return x.Id != y.Id;
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
                var zip = Unsafe.ReadUnaligned<uint>(ref MemoryMarshal.GetReference(value)) & 0x00ffffffu;
                // DEF
                if (zip == 4605252u)
                {
                    algorithm = Deflate;
                    return true;
                }
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
                ThrowHelper.ThrowNotSupportedException_Algorithm(Encoding.UTF8.GetString(value));
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

            return value.Utf8Name;
        }

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }
    }
}
