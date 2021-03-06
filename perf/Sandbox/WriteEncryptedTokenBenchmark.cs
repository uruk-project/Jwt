﻿using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class WriteEncryptedTokenBenchmark : WriteEncryptedToken
    {
        public override IEnumerable<string> GetPayloads()
        {
            yield return "JWE 6 claims";
            yield return "JWE 16 claims";
        }
    }
}