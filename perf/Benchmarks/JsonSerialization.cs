using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JsonSerilization
    {
        static IDictionary<string, object> dictionary = new Dictionary<string, object>()
        {
            { "sub", "sub value" },
            { "jti", "1234567890" },
            { "exp", 12345678 },
            { "aud", new JArray(new[] { "https://example.org", "abcdef" }) },
            { "nbf", 23456789 }
        };

        static IDictionary<string, object> dictionaryMedium = new Dictionary<string, object>()
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

        static JObject json = JObject.FromObject(dictionary);

        static JObject jsonMedium = JObject.FromObject(dictionaryMedium);

        static dynamic dyn = new
        {
            sub = "sub value",
            jti = "1234567890",
            exp = 12345678,
            aud = new JArray(new[] { "https://example.org", "abcdef" }),
            nbf = 23456789
        };

        static dynamic dynMedium = new
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

        [Benchmark(Baseline = true)]
        public void JsonObject()
        {
            JsonConvert.SerializeObject(json);
        }

        [Benchmark]
        public void JsonObject_Medium()
        {
            JsonConvert.SerializeObject(jsonMedium);
        }

        [Benchmark]
        public void Dictionary()
        {
            JsonConvert.SerializeObject(dictionary);
        }

        [Benchmark]
        public void Dictionary_Medium()
        {
            JsonConvert.SerializeObject(dictionaryMedium);
        }

        [Benchmark]
        public void Dynamic()
        {
            JsonConvert.SerializeObject(dyn);
        }

        [Benchmark]
        public void Dynamic_Medium()
        {
            JsonConvert.SerializeObject(dynMedium);
        }
    }
}
