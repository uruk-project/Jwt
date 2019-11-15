using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Loggers;
using BenchmarkDotNet.Toolchains.CsProj;
using BenchmarkDotNet.Toolchains.DotNetCli;
using BenchmarkDotNet.Validators;

namespace JsonWebToken.Performance
{
    internal class AllTfmCoreConfig : ManualConfig
    {
        public AllTfmCoreConfig()
        {
            Add(ConsoleLogger.Default);
            Add(MarkdownExporter.GitHub);
            Add(MemoryDiagnoser.Default);
            Add(StatisticColumn.OperationsPerSecond);
            Add(DefaultColumnProviders.Instance);

            Add(JitOptimizationsValidator.FailOnError);
            Add(BenchmarkLogicalGroupRule.ByCategory);

            //Add(Job.Core
            //    .With(CsProjCoreToolchain.From(NetCoreAppSettings.NetCoreApp20))
            //    .With(new GcMode { Server = true }));

            Add(Job.Default
                .With(CoreRuntime.Core21) 
                .With(new GcMode { Server = true }));

            Add(Job.Default
                .With(CoreRuntime.Core30)
                .With(new GcMode { Server = true }));
        }
    }
}
