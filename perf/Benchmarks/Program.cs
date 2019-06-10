using BenchmarkDotNet.Running;
using System.Reflection;

namespace JsonWebToken.Performance
{
    class Program
    {
        static void Main(string[] args)
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
#if DEBUG
            BenchmarkSwitcher.FromAssembly(typeof(Program).GetTypeInfo().Assembly).Run(args, new DebugInProcessConfig());
#else
            BenchmarkSwitcher.FromAssembly(typeof(Program).GetTypeInfo().Assembly).Run(args);
#endif
        }
    }
}
