using System;
using Xunit;
using Xunit.Abstractions;

namespace JsonWebToken.Tools.Jwk.Tests
{
    public class EncryptCommandTests
    {
        private readonly ITestOutputHelper _output;

        public EncryptCommandTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [InlineData("Hello", "P@ssw0rd", 100u, 8u, "./input.jwk", "./output.jwk")]
        [InlineData("Hello", "P@ssw0rd", 100u, null, "./input.jwk", "./output.jwk")]
        [InlineData("Hello", "P@ssw0rd", null, 8u, "./input.jwk", "./output.jwk")]
        [InlineData("Hello", "P@ssw0rd", null, null, "./input.jwk", "./output.jwk")]
        [InlineData("Hello", "P@ssw0rd", 100u, 8u, null, "./output.jwk")]
        [InlineData("Hello", "P@ssw0rd", 100u, 8u, "./input.jwk", null)]
        [InlineData("Hello", "P@ssw0rd", 100u, 8u, null, null)]
        [Theory]
        public void Execute_Success(string? input, string password, uint? iterationCount, uint? saltSize, string? inputPath, string? outputPath)
        {
            var command = new EncryptCommand(input, password, iterationCount, saltSize, inputPath, outputPath);

            TestStore store = new TestStore(input);
            TestReporter reporter = new TestReporter(_output);
            TestConsole console = new TestConsole(_output);
            command.Execute(new CommandContext(store, reporter, console));

            if (inputPath is null)
            {
                Assert.False(store.WasRead);
            }
            else
            {
                Assert.True(store.WasRead);
            }

            if (outputPath is null)
            {
                Assert.Null(store.Output);
                Assert.False(store.WasWritten);
                var output = console.GetOutput();
                Assert.NotEqual(0, output.Length);
            }
            else
            {
                Assert.NotNull(store.Output);
                Assert.True(store.WasWritten);
                var output = console.GetOutput();
                Assert.Equal(0, output.Length);
            }
        }

        [InlineData(null, "P@ssw0rd", 100u, 8u, null, "./output.jwk")]
        [Theory]
        public void Execute_Fail(string? input, string password, uint? iterationCount, uint? saltSize, string? inputPath, string? outputPath)
        {
            var command = new EncryptCommand(input, password, iterationCount, saltSize, inputPath, outputPath);

            TestStore store = new TestStore(input);
            TestReporter reporter = new TestReporter(_output);
            TestConsole console = new TestConsole(_output);
            Assert.Throws< InvalidOperationException>(() => command.Execute(new CommandContext(store, reporter, console)));
        }
    }
}
