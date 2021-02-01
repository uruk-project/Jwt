using System;
using System.CommandLine.IO;
using System.CommandLine.Parsing;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace JsonWebToken.Tools.Jwk.Tests
{
    public class DecryptCommandTests
    {
        private const string _encryptedJwk = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiMnd3U0ZpSFRvV0J1VzdNR180Q1UtTkY3cFVRcTFYd3ZiZUZwX01HdGdNVSIsImN0eSI6Imp3aytqc29uIiwicDJzIjoiUTZEaUNlY2ZjeDgiLCJwMmMiOjEwMDB9.rbei-XOebRrEC4wD8vgU1W0CiGY0AaBi4qJ3Ps6aYon1j2-ouHnJDA.lWjd9VRcSheDachaOFm1Ag.1eP7inmoYObCHupq6Ri9Fub9eg-eVxCH8ZkwuO0W3hhx-2bAhNDvYGqsk6uw296Hm8brgw3OC8v0LMYCqG9KAcyffrLDjwwBl31L6xaJYBqJcq3OyBEhjQMpS0hp51Iv.1AtgT-heRLixLFo2n5hTnQ";

        private readonly ITestOutputHelper _output;

        public DecryptCommandTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [InlineData(_encryptedJwk, "P@ssw0rd", 100u, 8u, "./input.jwk", "./output.jwk")]
        [InlineData(_encryptedJwk, "P@ssw0rd", 100u, null, "./input.jwk", "./output.jwk")]
        [InlineData(_encryptedJwk, "P@ssw0rd", null, 8u, "./input.jwk", "./output.jwk")]
        [InlineData(_encryptedJwk, "P@ssw0rd", 100u, 8u, null, "./output.jwk")]
        [InlineData(_encryptedJwk, "P@ssw0rd", 100u, 8u, "./input.jwk", null)]
        [InlineData(_encryptedJwk, "P@ssw0rd", 100u, 8u, null, null)]
        [Theory]
        public async Task Execute(string? input, string password, uint? iterationCount, uint? saltSize, string? inputPath, string? outputPath)
        {
            TestStore store = new TestStore(input);
            var command = new DecryptCommand(input, password, iterationCount, saltSize, inputPath is null ? null : new FileInfo(inputPath), outputPath is null ? null : new FileInfo(outputPath), true, store);

            TestConsole console = new TestConsole();
            new Parser();
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
            var command = new DecryptCommand(input, password, iterationCount, saltSize, inputPath is null ? null : new FileInfo(inputPath), outputPath is null ? null : new FileInfo(outputPath), true, store);

            TestConsole console = new TestConsole();
            Assert.ThrowsAsync<InvalidOperationException>(() => command.InvokeAsync(console));
        }
    }
}
