using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;

namespace JsonWebToken.Performance
{
    internal class SimdCoreConfig : ManualConfig
    {
        public SimdCoreConfig()
        {
            AddJob(Job.Default.WithId("AVX"));

            AddJob(Job.Default
                .WithEnvironmentVariable(new EnvironmentVariable("COMPlus_EnableAVX", "0"))
                .WithId("SSSE"));

            AddJob(Job.Default
                .WithEnvironmentVariable(new EnvironmentVariable("COMPlus_EnableSSE", "0"))
                .WithId("Scalar"));
        }
    }
}
