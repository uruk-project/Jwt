using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using Jose;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class StringEquals
    {
        private string algorithm = "fake";

        [Benchmark(Baseline = true)]
        public bool Equals_Ordinal()
        {
            var algorithm = "fake";
            if (string.Equals(algorithm, SecurityAlgorithms.RsaSha256, StringComparison.Ordinal)
                || string.Equals(algorithm, SecurityAlgorithms.RsaSha384, StringComparison.Ordinal)
                || string.Equals(algorithm, SecurityAlgorithms.RsaSha512, StringComparison.Ordinal)
                || string.Equals(algorithm, SecurityAlgorithms.RsaOaep, StringComparison.Ordinal)
                || string.Equals(algorithm, SecurityAlgorithms.RsaSha256, StringComparison.Ordinal))
                return true;
            return false;
        }

        [Benchmark]
        public bool Equals_Unspecified()
        {
            var algorithm = "fake";
            if (string.Equals(algorithm, SecurityAlgorithms.RsaSha256)
                || string.Equals(algorithm, SecurityAlgorithms.RsaSha384)
                || string.Equals(algorithm, SecurityAlgorithms.RsaSha512)
                || string.Equals(algorithm, SecurityAlgorithms.RsaOaep)
                || string.Equals(algorithm, SecurityAlgorithms.RsaSha256))
                return true;
            return false;
        }


        [Benchmark]
        public bool Switch()
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaOaep:
                case SecurityAlgorithms.RsaPkcs1:
                    return true;
            }

            return false;
        }
    }
}
