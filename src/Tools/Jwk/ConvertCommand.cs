using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.CommandLineUtils;

namespace JsonWebToken.Tools.Jwk
{
    internal class ConvertCommand : ICommand
    {
        private string _format;
        private readonly string? _certificatePassword;
        private readonly string? _password;
        private readonly uint _iterationCount;
        private readonly uint _saltSize;
        private string _inputPath;
        private string? _outputPath;
        private readonly bool _force;

        public ConvertCommand(string format, string? certificatePassword, string? password, uint? iterationCount, uint? saltSize, string inputPath, string? outputPath, bool force)
        {
            _format = format;
            _certificatePassword = certificatePassword;
            _password = password;
            _iterationCount = iterationCount ?? 1000;
            _saltSize = saltSize ?? 8;
            _inputPath = inputPath;
            _outputPath = outputPath;
            _force = force;
        }

        public static void Configure(CommandLineApplication command, CommandLineOptions options)
        {
            command.Description = "Convert a key to JWK format";
            command.ExtendedHelpText =
@"Examples:
  dotnet jwk convert -i ./key.pem -f PEM -o ./key.jwk
  dotnet jwk convert -i ./key.crt -f X509 -o ./key.jwk
  dotnet jwk convert -i ./key.crt -f X509 -p P@ssw0rd -o ./key.jwk";

            command.HelpOption();

            var formatOption = command.Option("-f|--format <FORMAT>", "The input format to read from. Valid values are 'PEM' and 'X509'.", CommandOptionType.SingleValue);
            var inputPathOption = command.Option("-i|--input-path <INPUT_PATH>", "The plain key input path. Use this option when the key is stored into a file.", CommandOptionType.SingleValue);
            var certificatePasswordOption = command.Option("--certificate-password <CERTIFICATE_PASSWORD>", "The password of the certificate.", CommandOptionType.SingleValue);
            var outputPathOption = command.Option("-o|--output-path <OUTPUT_PATH>", "The encrypted key output path", CommandOptionType.SingleValue);
            var passwordOption = command.Option("-p|--password <PASSWORD>", "The password used to encrypt the key.", CommandOptionType.SingleValue);
            var iterationCountOption = command.Option("--iteration-count <ITERATION_COUNT>", "The iteration count used for the password derivation.", CommandOptionType.SingleValue);
            var saltSizeOption = command.Option("--salt-size <SALT_SIZE>", "The salt size in bytes used for the password derivation.", CommandOptionType.SingleValue);
            var forceOption = command.Option("--force", "Erase the output file whether it exist.", CommandOptionType.NoValue);

            command.OnExecute(() =>
            {
                if (!inputPathOption.HasValue())
                {
                    throw new CommandParsingException(command, "Missing option -i.");
                }

                if (!formatOption.HasValue())
                {
                    throw new CommandParsingException(command, "Missing option -f.");
                }

                if (!formatOption.HasValue())
                {
                    throw new CommandParsingException(command, "Missing option -f.");
                }

                if (iterationCountOption.HasValue() && !certificatePasswordOption.HasValue())
                {
                    throw new CommandParsingException(command, "Invalid option --iteration-count: you must specify a password with the option -p.");
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

                if (saltSizeOption.HasValue() && !certificatePasswordOption.HasValue())
                {
                    throw new CommandParsingException(command, "Invalid option --salt-size: you must specify a password with the option -p.");
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

                switch (formatOption.Value())
                {
                    case "PEM":
                        if (certificatePasswordOption.HasValue())
                        {
                            throw new CommandParsingException(command, "Invalid option -p. PEM format with a password is not supported.");
                        }
                        break;
                    case "X509":
                        break;
                    default:
                        throw new CommandParsingException(command, "Invalid option -f. Valid values are 'PEM' and 'X509'.");
                }

                options.Command = new ConvertCommand(formatOption.Value(), certificatePasswordOption.Value(), passwordOption.Value(), iterationCount, saltSize, inputPathOption.Value(), outputPathOption.Value(), forceOption.HasValue());
            });
        }

        public void Execute(CommandContext context)
        {
            string key;
            switch (_format)
            {
                case "PEM":
                    key = ReadFromPem(context);
                    break;
                case "X509":
                    key = ReadFromX509(context);
                    break;
                default:
                    throw new InvalidOperationException($"Invalid input format '{_format}'.");
            }

            key = Transform(context, key);
            if (_outputPath is null)
            {
                context.Console.Out.Write(key);
            }
            else
            {
                context.Reporter.Verbose($"Writing JWK into file {_outputPath}.");
                context.Store.Write(_outputPath, key, _force);
                context.Reporter.Verbose("Done.");
            }
        }

        public string Transform(CommandContext context, string data)
        {
            if (_password != null)
            {
                var alg = KeyManagementAlgorithm.Pbes2HS256A128KW;
                var enc = EncryptionAlgorithm.A128CbcHS256;
                context.Reporter.Verbose(
$@"Encrypting the JWK...
Algorithm: {alg}
Encryption algorithm: {enc}
Password derivation iteration count: {_iterationCount}
Password derivation salt size: {_saltSize} bits");
                var encryptionKey = PasswordBasedJwk.FromPassphrase(_password, iterationCount: _iterationCount, saltSizeInBytes: _saltSize);
                var writer = new JwtWriter();
                var descriptor = new PlaintextJweDescriptor(encryptionKey, alg, enc)
                {
                    Payload = data
                };

                context.Reporter.Verbose("JWK encrypted.");
                return writer.WriteTokenString(descriptor);
            }

            return data;
        }

        private string ReadFromX509(CommandContext context)
        {
            context.Reporter.Verbose($"Reading X509 certificate from {_inputPath} file...");
            X509Certificate2 certificate = context.Store.LoadX509(_inputPath, _certificatePassword);
            if (!JsonWebToken.Jwk.TryReadPrivateKeyFromX509Certificate(certificate, out AsymmetricJwk? key))
            {
                context.Reporter.Verbose("No private key found. Reading X509 public key...");
                if (!JsonWebToken.Jwk.TryReadPublicKeyFromX509Certificate(certificate, out key))
                {
                    string? algorithm = Oid.FromOidValue(certificate.GetKeyAlgorithm(), OidGroup.All).FriendlyName;
                    throw new InvalidOperationException($"Unable to find a key the certificate. The certificate is for the algorithm '{algorithm}'.");
                }
            }

            context.Reporter.Verbose("X509 certificate successfully read.");
            return key.ToString();
        }

        private string ReadFromPem(CommandContext context)
        {
            context.Reporter.Verbose($"Reading PEM key from {_inputPath} file...");
            string pem = context.Store.Read(_inputPath);
            var key = JsonWebToken.Jwk.FromPem(pem);
            context.Reporter.Verbose("PEM key successfully read.");
            return key.ToString();
        }
    }
}
