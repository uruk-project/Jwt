using BenchmarkDotNet.Running;
using System.Reflection;

namespace JsonWebToken.Performance
{
    class Program
    {
        static void Main(string[] args)
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            BenchmarkSwitcher.FromAssembly(typeof(Program).GetTypeInfo().Assembly).Run(args);
        }
    }
}
