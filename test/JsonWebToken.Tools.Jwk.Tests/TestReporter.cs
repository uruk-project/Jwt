using Xunit.Abstractions;

namespace JsonWebToken.Tools.Jwk.Tests
{
    public class TestReporter : IReporter
    {
        private readonly ITestOutputHelper _output;

        public TestReporter(ITestOutputHelper output)
        {
            _output = output;
        }

        public void Verbose(string message)
        {
            _output.WriteLine("verbose: " + message);
        }

        public void Output(string message)
        {
            _output.WriteLine("output: " + message);
        }

        public void Warn(string message)
        {
            _output.WriteLine("warn: " + message);
        }

        public void Error(string message)
        {
            _output.WriteLine("error: " + message);
        }
    }
}
