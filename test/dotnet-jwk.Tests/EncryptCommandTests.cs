using System;
using System.CommandLine.IO;
using System.IO;
using System.Threading.Tasks;
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
        public async Task Execute_Success(string? input, string password, uint? iterationCount, uint? saltSize, string? inputPath, string? outputPath)
        {
            TestStore store = new TestStore(input);
            var command = new EncryptCommand(input, password, iterationCount, saltSize, inputPath is null ? null : new FileInfo(inputPath), outputPath is null ? null : new FileInfo(outputPath), true, store);

            TestConsole console = new TestConsole();
            await command.InvokeAsync(console);

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
                var output = console.Out.ToString()!;
                Assert.NotEqual(0, output.Length);
            }
            else
            {
                Assert.NotNull(store.Output);
                Assert.True(store.WasWritten);
                var output = console.Out.ToString()!;
                Assert.Equal(0, output.Length);
            }
        }

        [InlineData(null, "P@ssw0rd", 100u, 8u, null, "./output.jwk")]
        [Theory]
        public void Execute_Fail(string? input, string password, uint? iterationCount, uint? saltSize, string? inputPath, string? outputPath)
        {
            TestStore store = new TestStore(input);
            var command = new EncryptCommand(input, password, iterationCount, saltSize, inputPath is null ? null : new FileInfo(inputPath), outputPath is null ? null : new FileInfo(outputPath), true, store);

            TestConsole console = new TestConsole();
            Assert.ThrowsAsync<InvalidOperationException>(() => command.InvokeAsync(console));
        }
    }
}
