using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Loggers;
using BenchmarkDotNet.Validators;

namespace JsonWebToken.Performance
{
    internal class AllTfmCoreConfig : ManualConfig
    {
        public AllTfmCoreConfig()
        {
            AddLogger(ConsoleLogger.Default);
            AddExporter(MarkdownExporter.GitHub);
            AddDiagnoser(MemoryDiagnoser.Default);
            AddColumn(StatisticColumn.OperationsPerSecond);
            AddColumnProvider(DefaultColumnProviders.Instance);

            AddValidator(JitOptimizationsValidator.FailOnError);
            AddLogicalGroupRules(BenchmarkLogicalGroupRule.ByCategory);

            AddJob(Job.Default
                .WithGcMode(new GcMode { Server = true })
                .WithRuntime(CoreRuntime.Core31));
        }
    }
}
