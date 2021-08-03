using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    [DisassemblyDiagnoser]
    public class StructCopyBenchmark
    {
        [Params(true, false)]
        public bool includePrivateParameters;

        private ECParameters _parameters = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = new byte[32], Q = new ECPoint { X = new byte[32], Y = new byte[32] } };

        [Benchmark(Baseline = true)]
        public ECParameters ExportParameters_Old()
        {
            var parameters = new ECParameters
            {
                Q = _parameters.Q,
                Curve = _parameters.Curve
            };
            if (includePrivateParameters)
            {
                parameters.D = _parameters.D;
            }

            return parameters;
        }

        [Benchmark]
        public ECParameters ExportParameters_Old2()
        {
            var parameters = new ECParameters
            {
                Q = _parameters.Q,
                Curve = _parameters.Curve
            };
                parameters.D = includePrivateParameters ? _parameters.D : null;

            return parameters;
        }
        [Benchmark]
        public ECParameters ExportParameters_Brute()
        {
            return _parameters;
        }
        [Benchmark]
        public ECParameters ExportParameters_Brute2()
        {
            var p = _parameters;
            return p;
        }

        [Benchmark]
        public ECParameters ExportParameters_New()
        {
            var parameters = _parameters;

            if (!includePrivateParameters)
            {
                parameters.D = null;
            }

            return parameters;
        }
    }
}
