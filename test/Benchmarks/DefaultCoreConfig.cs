using System.Collections.Generic;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Loggers;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Toolchains.CsProj;
using BenchmarkDotNet.Toolchains.DotNetCli;
using BenchmarkDotNet.Validators;

namespace JsonWebTokens.Performance
{
    internal class DefaultCoreConfig : ManualConfig
    {
        public DefaultCoreConfig()
        {
            Add(MarkdownExporter.GitHub);

            Add(MemoryDiagnoser.Default);
            Add(StatisticColumn.OperationsPerSecond);
            Add(DefaultColumnProviders.Instance);

            Add(JitOptimizationsValidator.FailOnError);
            Add(DefaultColumnProviders.Instance);

            Add(Job.Core
                .With(CsProjCoreToolchain.From(NetCoreAppSettings.NetCoreApp21))
                .With(new GcMode { Server = true })
                .With(RunStrategy.Throughput));
            
            //Add(Job.Core
            //    .With(CsProjCoreToolchain.From(NetCoreAppSettings.NetCoreApp20))
            //    .With(new GcMode { Server = true })
            //    .With(RunStrategy.Throughput));
        }
    }

    public class ColumnProvider : IColumnProvider
    {
        public IEnumerable<IColumn> GetColumns(Summary summary)
        {
            return null;
            //return DefaultColumnProviders.Instance;
        }
    }
}
