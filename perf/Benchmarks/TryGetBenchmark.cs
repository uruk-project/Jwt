using System;
using System.Collections.Generic;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using Newtonsoft.Json.Linq;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class TryGetBenchmark
    {
        static readonly IDictionary<string, object> dictionary = new Dictionary<string, object>()
        {
            { "sub", "sub value" },
            { "jti", "1234567890" },
            { "exp", 12345678 },
            { "aud", new JArray(new[] { "https://example.org", "abcdef" }) },
            { "nbf", 23456789 }
        };

        static readonly IDictionary<string, object> dictionaryMedium = new Dictionary<string, object>()
        {
            { "sub", "sub value" },
            { "jti", "1234567890" },
            { "exp", 12345678 },
            { "aud", new JArray(new[] { "https://example.org", "abcdef" }) },
            { "nbf", 23456789 },
            { "claim0", "".PadRight(100, 'a') },
            { "claim1", "".PadRight(100, 'b') },
            { "claim2", "".PadRight(100, 'c') },
            { "claim3", "".PadRight(100, 'd') },
            { "claim4", "".PadRight(100, 'e') },
            { "claim5", "".PadRight(100, 'f') },
            { "claim6", "".PadRight(100, 'g') },
            { "claim7", "".PadRight(100, 'h') },
            { "claim8", "".PadRight(100, 'i') },
            { "claim9", "".PadRight(100, 'j') }
        };

        static readonly JObject json = JObject.FromObject(dictionary);

        static readonly JObject jsonMedium = JObject.FromObject(dictionaryMedium);

        static readonly JwtObject jwtObject = Tokens.ToJwtObject(jsonMedium);

        static readonly dynamic dyn = new
        {
            sub = "sub value",
            jti = "1234567890",
            exp = 12345678,
            aud = new JArray(new[] { "https://example.org", "abcdef" }),
            nbf = 23456789
        };

        static readonly dynamic dynMedium = new
        {
            sub = "sub value",
            jti = "1234567890",
            exp = 12345678,
            aud = new JArray(new[] { "https://example.org", "abcdef" }),
            nbf = 23456789,
            claim0 = "".PadRight(100, 'a'),
            claim1 = "".PadRight(100, 'b'),
            claim2 = "".PadRight(100, 'c'),
            claim3 = "".PadRight(100, 'd'),
            claim4 = "".PadRight(100, 'e'),
            claim5 = "".PadRight(100, 'f'),
            claim6 = "".PadRight(100, 'g'),
            claim7 = "".PadRight(100, 'h'),
            claim8 = "".PadRight(100, 'i'),
            claim9 = "".PadRight(100, 'j')
        };

        private readonly List<Slot> _properties = new List<Slot>();

        public TryGetBenchmark()
        {
            _properties.Clear();
            for (int i = 0; i < jwtObject.Count; i++)
            {
                _properties.Add(new Slot(jwtObject[i].Utf8Name.GetHashCode(), jwtObject[i]));
            }
        }

        private static readonly byte[] _fakeUtf8 = Encoding.UTF8.GetBytes("fake");

        [Benchmark(Baseline = true)]
        public bool ROS()
        {
            return TryGetValue(_fakeUtf8.AsSpan(), out var value);
        }

        [Benchmark]
        public bool ROM_NoHS()
        {
            return TryGetValueNoHashCode(_fakeUtf8.AsMemory(), out var value);
        }

        [Benchmark]
        public bool ROM()
        {
            return TryGetValue(_fakeUtf8.AsMemory(), out var value);
        }

        public bool TryGetValue(ReadOnlySpan<byte> key, out JwtProperty value)
        {
            for (int i = 0; i < _properties.Count; i++)
            {
                var current = _properties[i];
                if (current.Property.Utf8Name.SequenceEqual(key))
                {
                    value = current.Property;
                    return true;
                }
            }

            value = default;
            return false;
        }

        public bool TryGetValue(ReadOnlyMemory<byte> key, out JwtProperty value)
        {
            var hashCode = key.GetHashCode();
            var span = key.Span;
            for (int i = 0; i < _properties.Count; i++)
            {
                var current = _properties[i];
                if (current.HashCode == hashCode && current.Property.Utf8Name.SequenceEqual(span))
                {
                    value = current.Property;
                    return true;
                }
            }

            value = default;
            return false;
        }

        public bool TryGetValueNoHashCode(ReadOnlyMemory<byte> key, out JwtProperty value)
        {
            var span = key.Span;
            for (int i = 0; i < _properties.Count; i++)
            {
                var current = _properties[i];
                if (current.Property.Utf8Name.SequenceEqual(span))
                {
                    value = current.Property;
                    return true;
                }
            }

            value = default;
            return false;
        }

        private readonly struct Slot
        {
            public readonly int HashCode;

            public readonly JwtProperty Property;

            public Slot(int hashCode, JwtProperty property)
            {
                HashCode = hashCode;
                Property = property;
            }
        }

    }
}
