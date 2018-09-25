using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class CompressionAlgorithm : IEquatable<CompressionAlgorithm>
    {
        public static readonly CompressionAlgorithm Empty = new CompressionAlgorithm(id: 0, string.Empty, Compressor.Null);

        public static readonly CompressionAlgorithm Deflate = new CompressionAlgorithm(id: 1, "DEF", new DeflateCompressor());
        //public static readonly CompressionAlgorithm GZip = new CompressionAlgorithm(id: 2, "ZIP", new GZipCompressor());
        //#if NETCOREAPP2_1
        //public static readonly CompressionAlgorithm Brotli = new CompressionAlgorithm(id: 3, "BRO", new BrotliCompressor());
        //#endif

        public static readonly IDictionary<string, CompressionAlgorithm> AdditionalAlgorithms = new Dictionary<string, CompressionAlgorithm>();

        public sbyte Id { get; }

        public string Name { get; }

        public Compressor Compressor { get; }

        public CompressionAlgorithm(sbyte id, string name, Compressor compressor)
        {
            Id = id;
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Compressor = compressor ?? throw new ArgumentNullException(nameof(compressor));
        }

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
            switch (value)
            {
                case "DEF":
                    return Deflate;
                //case "ZIP":
                //    return GZip;
                //#if NETCOREAPP2_1
                //case "BRO":
                //    return Brotli;
                //#endif

                case null:
                case "":
                    return Empty;
            }

            if (!AdditionalAlgorithms.TryGetValue(value, out var algorithm))
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
