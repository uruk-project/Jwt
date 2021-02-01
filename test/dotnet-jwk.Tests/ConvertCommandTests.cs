using System.CommandLine.IO;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tools.Jwk.Tests
{
    public class ConvertCommandTests
    {
        public const string _certificatePassword = "SelfSigned2048_SHA512";

        public const string _certificateRaw = @"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";
        private const string Pkcs8PemECPrivateKey = @"
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcKEsLbFoRe1W/2jP
whpHKz8E19aFG/Y0ny19WzRSs4qhRANCAASBAezkdGSm6tcM9ppuK9PYhpGjJi0i
y6T3Y16v8maAqNihK6YdWZI19n2ctNWPF4PTykPnjwpauqYkB5k2wMOp
-----END PRIVATE KEY-----";

        [InlineData(Pkcs8PemECPrivateKey, "./key.pem", "./output.jwk", null, null, null)]
        [InlineData(Pkcs8PemECPrivateKey, "./key.pem", "./output.jwk", "password", null, null)]
        [InlineData(Pkcs8PemECPrivateKey, "./key.pem", "./output.jwk", "password", 4096u, null)]
        [InlineData(Pkcs8PemECPrivateKey, "./key.pem", "./output.jwk", "password", null, 16u)]
        [InlineData(Pkcs8PemECPrivateKey, "./key.pem", "./output.jwk", "password", 4096u, 16u)]
        [InlineData(Pkcs8PemECPrivateKey, "./key.pem", null, null, null, null)]
        [Theory]
        public async Task Execute_Pem(string? data, string inputPath, string? outputPath, string? password, uint? iterationCount, uint? saltSize)
        {
            TestStore store = new TestStore(data, _certificateRaw);
            var command = new ConvertPemCommand(password, iterationCount, saltSize, new FileInfo(inputPath), outputPath is null ? null : new FileInfo(outputPath), true, store);

            TestConsole console = new TestConsole();
            await command.InvokeAsync(console);

            Assert.True(store.WasRead);
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

        [InlineData(_certificatePassword, null, "./input.jwk", "./output.jwk", null, null, null)]
        [InlineData(_certificatePassword, "./output.der", "./input.jwk", "./output.jwk", null, null, null)]
        [Theory]
        public async Task Execute_X509(string certificatePassword, string? data, string inputPath, string? outputPath, string? password, uint? iterationCount, uint? saltSize)
        {
            TestStore store = new TestStore(data, _certificateRaw);
            var command = new ConvertX509Command(certificatePassword, password, iterationCount, saltSize, new FileInfo(inputPath), outputPath is null ? null : new FileInfo(outputPath), true, store);

            TestConsole console = new TestConsole();
            await command.InvokeAsync(console);

            Assert.True(store.WasRead);
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

        [InlineData("BAD P@ssw0rd", null, "./input.jwk", "./output.jwk", null, null, null)]
        [Theory]
        public void Execute_Fail(string certificatePassword, string? data, string inputPath, string? outputPath, string? password, uint? iterationCount, uint? saltSize)
        {
            TestStore store = new TestStore(data, _certificateRaw);
            var command = new ConvertX509Command(certificatePassword, password, iterationCount, saltSize, new FileInfo(inputPath), outputPath is null ? null : new FileInfo(outputPath), true, store);

            TestConsole console = new TestConsole();
            Assert.ThrowsAnyAsync<CryptographicException>(() => command.InvokeAsync(console));
        }
    }
}
