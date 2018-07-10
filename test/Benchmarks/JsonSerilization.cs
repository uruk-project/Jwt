using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IdentityModel.Tokens.Jwt;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class JsonSerilization
    {
        JObject json = new JObject()
        {
            {"sub", "sub value" },
            {"jti", "1234567890" },
            {"exp", 12345678 },
            {"aud", new JArray(new[] { "https://example.org", "abcdef" }) },
            { "nbf", 23456789 }
        };

        IDictionary<string, object> dictionary = new Dictionary<string, object>()
        {
            {"sub", "sub value" },
            {"jti", "1234567890" },
            {"exp", 12345678 },
            {"aud", new JArray(new[] { "https://example.org", "abcdef" }) },
            { "nbf", 23456789 }
        };

        dynamic dyn = new
        {
            sub = "sub value",
            jti = "1234567890",
            exp = 12345678,
            aud = new JArray(new[] { "https://example.org", "abcdef" }),
            nbf = 23456789
        };

        ExpandoObject expando = CreateExpando();

        [Benchmark(Baseline = true)]
        public void JsonObject()
        {
            JsonConvert.SerializeObject(json);
        }

        [Benchmark]
        public void Dictionary()
        {
            JsonConvert.SerializeObject(dictionary);
        }

        [Benchmark]
        public void Dynamic()
        {
            JsonConvert.SerializeObject(dyn);
        }


        [Benchmark]
        public void Expando()
        {
            JsonConvert.SerializeObject(expando);
        }

        private static ExpandoObject CreateExpando()
        {
            var expando = new ExpandoObject();
            expando.TryAdd("sub", "sub value");
            expando.TryAdd("jti", "1234567890");
            expando.TryAdd("exp", 12345678);
            expando.TryAdd("aud", new JArray(new[] { "https://example.org", "abcdef" }));
            expando.TryAdd("nbf", 23456789);

            return expando;
        }
    }
}
