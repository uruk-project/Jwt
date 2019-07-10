// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Defines compression algorithm.
    /// </summary>
    public sealed class CompressionAlgorithm : IEquatable<CompressionAlgorithm>
    {
        /// <summary>
        /// Deflate
        /// </summary>
        public static readonly CompressionAlgorithm Deflate = new CompressionAlgorithm(id: 1, "DEF", new DeflateCompressor());

        // TODO : Verify the pertinence
        /// <summary>
        /// Gets the algorithm identifier. 
        /// </summary>
        public sbyte Id { get; }

        /// <summary>
        /// Gets the name of the compression algorithm.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Gets the name of the signature algorithm.
        /// </summary>
        public byte[] Utf8Name => Encoding.UTF8.GetBytes(Name);

        /// <summary>
        /// Gets the <see cref="Compressor"/>.
        /// </summary>
        public Compressor Compressor { get; }

        /// <summary>
        /// Gets the <see cref="SignatureAlgorithm"/> list; 
        /// </summary>
        public static Dictionary<string, CompressionAlgorithm> Algorithms { get; } = new Dictionary<string, CompressionAlgorithm>
        {
            { Deflate.Name, Deflate }
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="CompressionAlgorithm"/> class.
        /// </summary>
        /// <param name="id"></param>
        /// <param name="name"></param>
        /// <param name="compressor"></param>
        public CompressionAlgorithm(sbyte id, string name, Compressor compressor)
        {
            Id = id;
            if (name == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.name);
            }

            if (compressor == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.compressor);
            }

            Name = name;
            Compressor = compressor;
        }

        /// <summary>
        /// Determines whether this instance and a specified object, which must also be a
        /// <see cref="CompressionAlgorithm"/> object, have the same value.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
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
        public bool Equals(CompressionAlgorithm other)
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
        public static bool operator ==(CompressionAlgorithm x, CompressionAlgorithm y)
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
        public static bool operator !=(CompressionAlgorithm x, CompressionAlgorithm y)
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
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="SignatureAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="algorithm"></param>
        public unsafe static bool TryParse(ReadOnlySpan<byte> value, out CompressionAlgorithm algorithm)
        {
            if (value.IsEmpty)
            {
                algorithm = null;
                return true;
            }

            fixed (byte* pValue = value)
            {
                if (value.Length == 5)
                {
                    // DEF
                    if (*pValue == (byte)'D' && *(ushort*)(pValue + 1) == 17989u)
                    {
                        algorithm = Deflate;
                        return true;
                    }
                }

                algorithm = null;
                return false;
            }
        }

        /// <summary>
        /// Cast the <see cref="ReadOnlySpan{T}"/> into its <see cref="CompressionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static unsafe explicit operator CompressionAlgorithm(ReadOnlySpan<byte> value)
        {
            if (value.IsEmpty)
            {
                return null;
            }

            fixed (byte* pValue = value)
            {
                if (value.Length == 3 && *(short*)pValue == 17732 && *(pValue + 2) == (byte)'F' /* DEF */)
                {
                    return Deflate;
                }
            }

            var key = Encoding.UTF8.GetString(value.ToArray());
            if (!Algorithms.TryGetValue(key, out var algorithm))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(key);
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the array of <see cref="byte"/> into its <see cref="CompressionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static unsafe explicit operator CompressionAlgorithm(byte[] value)
        {
            if (value == null)
            {
                return null;
            }

            return (CompressionAlgorithm)new ReadOnlySpan<byte>(value);
        }

        /// <summary>
        /// Cast the <see cref="CompressionAlgorithm"/> into its <see cref="long"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator long(CompressionAlgorithm value)
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
        public static explicit operator byte[](CompressionAlgorithm value)
        {
            if (value is null)
            {
                return Array.Empty<byte>();
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
