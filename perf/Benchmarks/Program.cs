using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using System;
using System.IO;
using System.Reflection;
#if NETCOREAPP
using System.Runtime.Intrinsics.X86;
#endif

namespace JsonWebToken.Performance
{
    class Program
    {
        static void Main(string[] args)
        {
            PrintSimdInfo(Console.Out);
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
#if DEBUG
            BenchmarkSwitcher.FromAssembly(typeof(Program).GetTypeInfo().Assembly).Run(args, new DebugInProcessConfig());
#else
            BenchmarkSwitcher.FromAssembly(typeof(Program).GetTypeInfo().Assembly).Run(args);
#endif
        }

        public static void PrintSimdInfo(TextWriter writer)
        {
            string separator = new string('-', 20);

            writer.WriteLine(separator);
#if NETCOREAPP
            writer.WriteLine("SIMD-Info");
            writer.WriteLine($"Sse  : {Sse.IsSupported}");
            writer.WriteLine($"Sse2 : {Sse2.IsSupported}");
            writer.WriteLine($"Ssse3: {Ssse3.IsSupported}");
            writer.WriteLine($"Avx  : {Avx.IsSupported}");
            writer.WriteLine($"Avx2 : {Avx2.IsSupported}");
#else
            writer.WriteLine("HW intrinsics not supported / available");
#endif
            writer.WriteLine(separator);
        }
    }
}
