using System.CommandLine.IO;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Tools.Jwk.Tests
{
    public class CheckCommandTests
    {
        [InlineData("Basic 'oct' key", @"
{
    ""kty"": ""oct"",
    ""k"": ""Sm7nSOWIqLc8xMK5CRhEiePi9iNukStXhssrYdSiMk0""
}")]
        [Theory]
        public async Task Execute_Success(string description, string json)
        {
            TestStore store = new TestStore(json);
            var command = new CheckCommand(new FileInfo("./fake_file.json"), store);

            TestConsole console = new TestConsole();
            await command.InvokeAsync(console);

            Assert.True(store.WasRead);
            Assert.Null(store.Output);
            Assert.False(store.WasWritten);
            var output = console.Out.ToString()!;
            Assert.NotEqual(0, output.Length);
            Assert.True(true, description);
        }

        [InlineData("Empty string", @"")]
        [InlineData("Malformed JSON object", @"{
   ""alg"": ""RS256"",
    ""e"": ""AQAB"",
    ""kid"": ""JWT-Signature-Key"",
    ""n"": ""nehPQ7FQ1YK-leKyIg-aACZaT-DbTL5V1XpXghtLX_bEC-fwxhdE_4yQKDF6cA-V4c-5kh8wMZbfYw5xxgM9DynhMkVrmQFyYB3QMZwydr922UWs3kLz-nO6vi0ldCn-ffM9odUPRHv9UbhM5bB4SZtCrpr9hWQgJ3FjzWO2KosGQ8acLxLtDQfU_lq0OGzoj_oWwUKaN_OVfu80zGTH7mxVeGMJqWXABKd52ByvYZn3wL_hG60DfDWGV_xfLlHMt_WoKZmrXT4V3BCBmbitJ6lda3oNdNeHUh486iqaL43bMR2K4TzrspGMRUYXcudUQ9TycBQBrUlT85NRY9TeOw"",
    ""use"": ""sig""")]
        [Theory]
        public void Execute_Fail(string description, string json)
        {
            TestStore store = new TestStore(json);
            var command = new CheckCommand(new FileInfo("./fake_file.json"), store);

            TestConsole console = new TestConsole();
            Assert.ThrowsAnyAsync<JwkCheckException>(() => command.InvokeAsync(console));
            Assert.True(true, description);
        }
    }
}
