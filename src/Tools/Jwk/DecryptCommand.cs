using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    internal class DecryptCommand : TransformKeyCommand
    {
        internal static Command Create()
        {
            var command = new Command("decrypt", "Decrypts a JWK")
            {
                Handler = CommandHandler.Create(typeof(DecryptCommand).GetMethod(nameof(ICommandHandler.InvokeAsync), new[] { typeof(InvocationContext) })!)
            }
            .OptionalKeyValue("The key to encrypt")
            .OptionalInputPath("The plain key input path. Use this option when the key is stored into a file.")
            .OptionalPrivateKeyOutputPath()
            .RequiredEncryptionPassword()
            .Force()
            .Verbose();

            return command;
        }

        public DecryptCommand(string? key, string password, uint? iterationCount, uint? saltSize, FileInfo? inputPath, FileInfo? outputPath, bool force, IStore store)
            : base(key, password, iterationCount, saltSize, inputPath, outputPath, force, store)
        {
        }

        public override Task<int> InvokeAsync(InvocationContext context)
            => base.InvokeAsync(context);

        public override string Transform(IConsole console, string data)
        {
            console.Verbose($@"Decrypting the JWK...
Password derivation iteration count: {_iterationCount}
Password derivation salt size: {_saltSize} bits");
            var decryptionKey = PasswordBasedJwk.FromPassphrase(_password, _iterationCount, _saltSize);
            var policy = new TokenValidationPolicyBuilder().WithDecryptionKeys(decryptionKey).IgnoreNestedToken().AcceptUnsecureTokenByDefault().Build();
            Jwt? jwt = null;
            try
            {
                if (!Jwt.TryParse(data, policy, out jwt))
                {
                    throw new InvalidOperationException($"Failed to decrypt the key.\n{jwt.Error!.Status}\n{jwt.Error!.Message}");
                }

                console.Verbose("JWK decrypted.");
                return jwt.Plaintext;
            }
            finally
            {
                jwt?.Dispose();
            }
        }
    }
}
