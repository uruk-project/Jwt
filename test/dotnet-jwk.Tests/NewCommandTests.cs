using System;
using System.Collections.Generic;
using System.CommandLine.IO;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tools.Jwk.Tests
{
    public class NewCommandTests
    {
        [InlineData("./output.jwk", null, null, null, 128, "HS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", "password", null, null, 128, "HS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", "password", 4096u, null, 128, "HS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", "password", null, 16u, 128, "HS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", "password", 4096u, 16u, 128, "HS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", "password", 4096u, 16u, 256, "HS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, null, null, 128, null, null, null, null, false, false)]
        [InlineData("./output.jwk", null, null, null, 0, "HS256", null, null, null, false, false)]
        [InlineData("./output.jwk", null, null, null, 0, "A128KW", null, null, null, false, false)]
        [InlineData("./output.jwk", null, null, null, 128, null, null, null, null, true, false)]
        [InlineData(null, null, null, null, 128, null, null, null, null, true, false)]
        [Theory]
        public async Task Execute_Symmetric(string? outputPath, string? password, uint? iterationCount, uint? saltSize, int length, string? alg, string? use, string?[] keyOps, string? kid, bool noKid, bool force)
        {
            TestStore store = new TestStore();
            var command = new NewCommand.NewSymmetricHandler(outputPath is null ? null : new FileInfo(outputPath), password, iterationCount, saltSize, length, alg, use, keyOps is null ? new List<string?>() : new List<string?>(keyOps), kid, noKid, force, store);

            TestConsole console = new TestConsole();
            await command.InvokeAsync(console);

            Assert.False(store.WasRead);
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

        [InlineData(null, null, null, null, 127, null, null, null, null, true, false)]
        [InlineData(null, null, null, null, 128, "X", null, null, null, false, false)]
        [InlineData(null, null, null, null, 128, "RS256", null, null, null, false, false)]
        [InlineData(null, null, null, null, 0, null, null, null, null, false, false)]
        [Theory]
        public void Execute_Symmetric_Fail(string? outputPath, string? password, uint? iterationCount, uint? saltSize, int length, string? alg, string? use, string?[] keyOps, string? kid, bool noKid, bool force)
        {
            TestStore store = new TestStore();
            var command = new NewCommand.NewSymmetricHandler(outputPath is null ? null : new FileInfo(outputPath), password, iterationCount, saltSize, length, alg, use, keyOps is null ? new List<string?>() : new List<string?>(keyOps), kid, noKid, force, store);

            TestConsole console = new TestConsole();
            Assert.ThrowsAnyAsync<InvalidOperationException>(() => command.InvokeAsync(console));
        }

        [InlineData("./output.jwk", null, null, null, null, 2048, "RS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, null, null, null, 2048, "RSA-OAEP", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", "./public.jwk", null, null, null, 2048, "RS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", null, null, 2048, "RS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", 4096u, null, 2048, "RS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", null, 16u, 2048, "RS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", 4096u, 16u, 2048, "RS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", 4096u, 16u, 4096, "RS256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, null, null, null, 2048, null, null, null, null, false, false)]
        [InlineData("./output.jwk", null, null, null, null, 2048, null, null, null, null, true, false)]
        [InlineData(null, null, null, null, null, 2048, null, null, null, null, true, false)]
        [Theory]
        public async Task Execute_Rsa(string? outputPath, string? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, int length, string? alg, string? use, string?[] keyOps, string? kid, bool noKid, bool force)
        {
            TestStore store = new TestStore();
            var command = new NewCommand.NewRsaHandler(outputPath is null ? null : new FileInfo(outputPath), publicOutputPath is null ? null : new FileInfo(publicOutputPath), password, iterationCount, saltSize, length, alg, use, keyOps is null ? new List<string?>() : new List<string?>(keyOps), kid, noKid, force, store);

            TestConsole console = new TestConsole();
            await command.InvokeAsync(console);

            Assert.False(store.WasRead);
            if (outputPath is null)
            {
                Assert.Null(store.Output);
                Assert.False(store.WasWritten);
                var output = console.Out.ToString()!;
                Assert.NotEqual(0, output.Length);
                Assert.Equal(outputPath, store.file1);
                if (publicOutputPath != null)
                {
                    Assert.Equal(publicOutputPath, store.file2);
                }

            }
            else
            {
                Assert.NotNull(store.Output);
                Assert.True(store.WasWritten);
                var output = console.Out.ToString()!;
                Assert.Equal(0, output.Length);
            }
        }

        [InlineData(null, null, null, null, null, 1023, null, null, null, null, true, false)]
        [InlineData(null, null, null, null, null, 2048, "X", null, null, null, false, false)]
        [InlineData(null, null, null, null, null, 2048, "HS256", null, null, null, false, false)]
        [InlineData(null, null, null, null, null, 0, null, null, null, null, false, false)]
        [Theory]
        public void Execute_Rsa_Fail(string? outputPath, string? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, int length, string? alg, string? use, string?[] keyOps, string? kid, bool noKid, bool force)
        {
            TestStore store = new TestStore();
            var command = new NewCommand.NewRsaHandler(outputPath is null ? null : new FileInfo(outputPath), publicOutputPath is null ? null : new FileInfo(publicOutputPath), password, iterationCount, saltSize, length, alg, use, keyOps is null ? new List<string?>() : new List<string?>(keyOps), kid, noKid, force, store);

            TestConsole console = new TestConsole();
            Assert.ThrowsAnyAsync<InvalidOperationException>(() => command.InvokeAsync(console));
        }


        [InlineData("./output.jwk", null, null, null, null, "P-256", "ES256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", "./public.jwk", null, null, null, "P-256", "ES256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", null, null, "P-256", "ES256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", 4096u, null, "P-256", "ES256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", null, 16u, "P-256", "ES256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", 4096u, 16u, "P-256", "ES256", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", 4096u, 16u, "P-256X", "ES256X", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", 4096u, 16u, "P-384", "ES384", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, "password", 4096u, 16u, "P-521", "ES512", "sig", new string[] { "sign" }, "billy", false, false)]
        [InlineData("./output.jwk", null, null, null, null, "P-256", null, null, null, null, false, false)]
        [InlineData("./output.jwk", null, null, null, null, "P-384", null, null, null, null, false, false)]
        [InlineData("./output.jwk", null, null, null, null, "P-521", null, null, null, null, false, false)]
        [InlineData("./output.jwk", null, null, null, null, "secp256k1", null, null, null, null, false, false)]
        [InlineData("./output.jwk", null, null, null, null, "P-256", null, null, null, null, true, false)]
        [InlineData(null, null, null, null, null, "P-256", null, null, null, null, true, false)]
        [Theory]
        public async Task Execute_EC(string? outputPath, string? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, string curve, string? alg, string? use, string?[] keyOps, string? kid, bool noKid, bool force)
        {
            TestStore store = new TestStore();
            var command = new NewCommand.NewECHandler(outputPath is null ? null : new FileInfo(outputPath), publicOutputPath is null ? null : new FileInfo(publicOutputPath), password, iterationCount, saltSize, curve, alg, use, keyOps is null ? new List<string?>() : new List<string?>(keyOps), kid, noKid, force, store);

            TestConsole console = new TestConsole();
            await command.InvokeAsync(console);

            Assert.False(store.WasRead);
            if (outputPath is null)
            {
                Assert.Null(store.Output);
                Assert.False(store.WasWritten);
                var output = console.Out.ToString()!;
                Assert.NotEqual(0, output.Length);
                Assert.Equal(outputPath, store.file1);
                if (publicOutputPath != null)
                {
                    Assert.Equal(publicOutputPath, store.file2);
                }

            }
            else
            {
                Assert.NotNull(store.Output);
                Assert.True(store.WasWritten);
                var output = console.Out.ToString()!;
                Assert.Equal(0, output.Length);
            }
        }

        [InlineData(null, null, null, null, null, "X", null, null, null, null, false, false)]
        [InlineData(null, null, null, null, null, "HS256", null, null, null, null, false, false)]
        [InlineData(null, null, null, null, null, null, null, null, null, null, false, false)]
        [InlineData(null, null, null, null, null, "P-256", "HS256", null, null, null, false, false)]
        [InlineData(null, null, null, null, null, "P-256", "ES512", null, null, null, false, false)]
        [Theory]
        public void Execute_EC_Fail(string? outputPath, string? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, string curve, string? alg, string? use, string?[] keyOps, string? kid, bool noKid, bool force)
        {
            TestStore store = new TestStore();
            var command = new NewCommand.NewECHandler(outputPath is null ? null : new FileInfo(outputPath), publicOutputPath is null ? null : new FileInfo(publicOutputPath), password, iterationCount, saltSize, curve, alg, use, keyOps is null ? new List<string?>() : new List<string?>(keyOps), kid, noKid, force, store);

            TestConsole console = new TestConsole();
            Assert.ThrowsAnyAsync<InvalidOperationException>(() => command.InvokeAsync(console));
        }
    }
}
