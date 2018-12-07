// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Defines compression algorithm.
    /// </summary>
    public sealed class CompressionAlgorithm : IEquatable<CompressionAlgorithm>, IAlgorithm
    {
        /// <summary>
        /// Empty
        /// </summary>
        public static readonly CompressionAlgorithm Empty = new CompressionAlgorithm(id: 0, string.Empty, null);

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
        /// Gets the <see cref="Compressor"/>.
        /// </summary>
        public Compressor Compressor { get; }

        /// <summary>
        /// Gets the <see cref="SignatureAlgorithm"/> list; 
        /// </summary>
        public static Dictionary<string, CompressionAlgorithm> Algorithms { get; } = new Dictionary<string, CompressionAlgorithm>
        {
            { Deflate.Name, Deflate },
            { Empty.Name, Empty }
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
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Compressor = compressor ?? throw new ArgumentNullException(nameof(compressor));
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
        /// Cast the <see cref="CompressionAlgorithm"/> into its <see cref="string"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator string(CompressionAlgorithm value)
        {
            return value?.Name;
        }

        /// <summary>
        /// Cast the <see cref="string"/> into its <see cref="CompressionAlgorithm"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static explicit operator CompressionAlgorithm(string value)
        {
            if (value == null)
            {
                return Empty;
            }

            if (!Algorithms.TryGetValue(value, out var algorithm))
            {
                Errors.ThrowNotSupportedAlgorithm(value);
            }

            return algorithm;
        }

        /// <summary>
        /// Cast the <see cref="CompressionAlgorithm"/> into its <see cref="long"/> representation.
        /// </summary>
        /// <param name="value"></param>
        public static implicit operator long(CompressionAlgorithm value)
        {
            return value.Id;
        }

        /// <inheritsddoc />
        public override string ToString()
        {
            return Name;
        }
    }
}
