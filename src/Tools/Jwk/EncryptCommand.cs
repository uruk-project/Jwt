using Microsoft.Extensions.CommandLineUtils;

namespace JsonWebToken.Tools.Jwk
{
    internal class EncryptCommand : TransformKeyCommand
    {
        public EncryptCommand(string? value, string password, uint? iterationCount, uint? saltSize, string? inputPath, string? outputPath, bool force)
            : base(value, password, iterationCount, saltSize, inputPath, outputPath, force)
        {
        }

        public static void Configure(CommandLineApplication command, CommandLineOptions options)
        {
            command.Description = "Encrypts a JWK";
            command.ExtendedHelpText =
@"Examples:
  dotnet jwk encrypt -k {""kty"":[...]} -o ./key.jwk -p <password> --iteration-count 4096 --salt-size 16
  dotnet jwk encrypt -k {""kty"":[...]} -o ./key.jwk -p <password>
  dotnet jwk encrypt -i ./key.jwk -o ./encrypted_key.jwk -p <password>";

            command.HelpOption();

            var keyValueOption = command.Option("-k|--key <KEY>", "The key to encrypt", CommandOptionType.SingleValue);
            var inputPathOption = command.Option("-i|--input-path <INPUT_PATH>", "The plain key input path. Use this option when the key is stored into a file.", CommandOptionType.SingleValue);
            var outputPathOption = command.Option("-o|--output-path <OUTPUT_PATH>", "The encrypted key output path", CommandOptionType.SingleValue);
            var passwordOption = command.Option("-p|--password <PASSWORD>", "The password used to encrypt the key", CommandOptionType.SingleValue);
            var iterationCountOption = command.Option("--iteration-count <ITERATION_COUNT>", "The iteration count used for the password derivation.", CommandOptionType.SingleValue);
            var saltSizeOption = command.Option("--salt-size <SALT_SIZE>", "The salt size in bytes used for the password derivation.", CommandOptionType.SingleValue);
            var forceOption = command.Option("--force", "Erase the output file whether it exist.", CommandOptionType.NoValue);

            command.OnExecute(() =>
            {
                if (!(keyValueOption.HasValue() ^ inputPathOption.HasValue()))
                {
                    throw new CommandParsingException(command, "You must specify the option -k or the option -i.");
                }

                if (!passwordOption.HasValue())
                {
                    throw new CommandParsingException(command, "Missing option -p");
                }

                uint? iterationCount = default;
                if (iterationCountOption.HasValue())
                {
                    if (!uint.TryParse(iterationCountOption.Value(), out uint iterationCountTmp))
                    {
                        throw new CommandParsingException(command, "Invalid option --iteration-count: you must specify an integer value greater than 1.");
                    }
                    else
                    {
                        iterationCount = iterationCountTmp;
                    }
                }

                uint? saltSize = default;
                if (saltSizeOption.HasValue())
                {
                    if (!uint.TryParse(saltSizeOption.Value(), out uint saltSizeTmp))
                    {
                        throw new CommandParsingException(command, "Invalid option --salt-size: you must specify an integer value greater than 1.");
                    }
                    else
                    {
                        saltSize = saltSizeTmp;
                    }
                }

                options.Command = new EncryptCommand(keyValueOption.Value(), passwordOption.Value(), iterationCount, saltSize, inputPathOption.Value(), outputPathOption.Value(), forceOption.HasValue());
            });
        }

        public override string Transform(CommandContext context, string data)
        {
            var alg = KeyManagementAlgorithm.Pbes2HS256A128KW;
            var enc = EncryptionAlgorithm.A128CbcHS256;

            context.Reporter.Verbose($@"Encrypting the JWK...
Algorithm: {alg}
Encryption algorithm: {enc}
Password derivation iteration count: {_iterationCount}
Password derivation salt size: {_saltSize} bits");
            var encryptionKey = PasswordBasedJwk.FromPassphrase(_password, iterationCount: _iterationCount, saltSizeInBytes: _saltSize);
            var writer = new JwtWriter();
            var descriptor = new PlaintextJweDescriptor(encryptionKey, KeyManagementAlgorithm.Pbes2HS256A128KW, EncryptionAlgorithm.A128CbcHS256)
            {
                Payload = data
            };
            var result =  writer.WriteTokenString(descriptor);
            context.Reporter.Verbose("JWK encrypted.");
            return result;
        }
    }
}
