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
        public static readonly CompressionAlgorithm Empty = new CompressionAlgorithm(id: 0, string.Empty, Compressor.Null);

        public static readonly CompressionAlgorithm Deflate = new CompressionAlgorithm(id: 1, "DEF", new DeflateCompressor());

        public sbyte Id { get; }

        public string Name { get; }

        public Compressor Compressor { get; }

        public static IDictionary<string, CompressionAlgorithm> Algorithms { get; } = new Dictionary<string, CompressionAlgorithm>
        {
            { Deflate.Name, Deflate },
            { Empty.Name, Empty }
        };

        public CompressionAlgorithm(sbyte id, string name, Compressor compressor)
        {
            Id = id;
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Compressor = compressor ?? throw new ArgumentNullException(nameof(compressor));
        }

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (obj is CompressionAlgorithm alg)
            {
                return Equals(alg);
            }

            return false;
        }

        public bool Equals(CompressionAlgorithm other)
        {
            if (other is null)
            {
                return false;
            }

            return Id == other.Id;
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }

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

        public static implicit operator string(CompressionAlgorithm value)
        {
            return value?.Name;
        }

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

        public static implicit operator long(CompressionAlgorithm value)
        {
            return value.Id;
        }

        public override string ToString()
        {
            return Name;
        }
    }
}
