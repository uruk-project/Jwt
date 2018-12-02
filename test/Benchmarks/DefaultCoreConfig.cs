using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Loggers;
using BenchmarkDotNet.Toolchains.CsProj;
using BenchmarkDotNet.Toolchains.DotNetCli;
using BenchmarkDotNet.Validators;

namespace JsonWebToken.Performance
{
    internal class DefaultCoreConfig : ManualConfig
    {
        public DefaultCoreConfig()
        {
            Add(ConsoleLogger.Default);
            Add(MarkdownExporter.GitHub);
            Add(StatisticColumn.OperationsPerSecond);
            Add(MemoryDiagnoser.Default);
            Add(StatisticColumn.OperationsPerSecond);
            Add(DefaultColumnProviders.Instance);

            Add(JitOptimizationsValidator.FailOnError);
            Add(BenchmarkLogicalGroupRule.ByCategory);

            Add(Job.Core
                .With(CsProjCoreToolchain.From(NetCoreAppSettings.NetCoreApp21))
                .With(new GcMode { Server = true }));
        }
    }

    public class HardwareIntrinsicsCustomConfig : ManualConfig
    {
        private const string EnableAVX2 = "COMPlus_EnableAVX2";
        private const string EnableSSSE3 = "COMPlus_EnableSSSE3";

        public HardwareIntrinsicsCustomConfig()
        {
            this.Add(Job.Core.WithId("AVX2"));

            this.Add(Job.Core
                .With(new[] { new EnvironmentVariable(EnableAVX2, "0") })
                .WithId("SSSE3"));

            this.Add(Job.Core
                .With(new[] { new EnvironmentVariable(EnableAVX2, "0"), new EnvironmentVariable(EnableSSSE3, "0") })
                .WithId("Scalar"));
        }
    }
}
