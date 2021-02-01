using System;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.IO;
using System.Linq;

namespace JsonWebToken.Tools.Jwk
{
    internal static class CommandExtensions
    {
        internal static Command Verbose(this Command command)
        {
            command.Add(new Option(new[] { "-v", "--verbose" }, "Show verbose output."));

            return command;
        }

        internal static Command RequireKeyLength(this Command command, int minValue, int maxValue, int modulo)
        {
            command.Add(new Option<int>(new[] { "-l", "--length" }, $"Length in bits of the key. Must be between {minValue} and {maxValue}.")
                   .KeyLength(minValue, maxValue, modulo));

            return command;
        }

        internal static Command RequireCurve(this Command command)
        {
            command.Add(new Option(new[] { "-c", "--curve" }, $"The elliptical curve name. Supported curves: {string.Join(", ", EllipticalCurve.SupportedCurves)}.")
            {
                IsRequired = true,
                Argument = new Argument
                {
                    Arity = ArgumentArity.ZeroOrOne
                }.FromAmong(EllipticalCurve.SupportedCurves.Select(c => c.Name.ToString()!).ToArray())
            });

            return command;
        }

        internal static Command RequireFormat(this Command command)
        {
            command.Add(new Option(new string[] { "-f", "--format" }, "The input format to read from. Valid values are 'PEM' and 'X509'.")
            {
                IsRequired = true,
                Argument = new Argument
                {
                    Arity = ArgumentArity.ExactlyOne
                }.FromAmong("PEM", "X509")
            });

            command.AddValidator(a => a.GetArgumentValueOrDefault<string>("-f") == "PEM" && a.Children.Contains("--certificate-password") ? "Invalid option -p. PEM format with a password is not supported." : null);

            return command;
        }

        internal static Command OptionalPrivateKeyOutputPath(this Command command)
            => OptionalOutputPath(command, "The private key output path.");

        internal static Command OptionalOutputPath(this Command command, string description)
        {
            command.Add(new Option<FileInfo>(new[] { "-o", "--output-path" }, description)
            {
                IsRequired = false
            }.LegalFilePathsOnly());

            return command;
        }

        internal static Command OptionalPublicKeyOutputPath(this Command command)
        {
            command.Add(new Option<FileInfo>("--public-output-path", "The public key output path.")
            {
                IsRequired = false
            }.LegalFilePathsOnly());

            return command;
        }

        internal static Command OptionalInputPath(this Command command)
            => command.InputPath("The file key input path. Use this option when the key is stored into a file.", isRequired: false);

        internal static Command RequiredInputPath(this Command command)
            => command.InputPath("The file key input path.", isRequired: true);

        private static Command InputPath(this Command command, string description, bool isRequired)
        {
            command.Add(new Option<FileInfo>(new[] { "-i", "--input-path" }, description)
            {
                IsRequired = isRequired
            }.LegalFilePathsOnly().ExistingOnly());

            return command;
        }

        internal static Command OptionalInputPath(this Command command, string description)
        {
            command.Add(new Option<FileInfo>(new[] { "-i", "--input-path" }, description)
            {
                IsRequired = false
            }.LegalFilePathsOnly());

            return command;
        }

        internal static Command OptionalKeyValue(this Command command, string description)
        {
            command.Add(new Option<string>(new[] { "-k", "--key" }, description)
            {
                IsRequired = false
            });
            command.AddValidator(a => a.Children.Contains("-i") && a.Children.Contains("-k") ? "The option -k is not compatible with the option -p." : null);

            return command;
        }

        internal static Command OptionalEncryptionPassword(this Command command)
            => Password(command, "The password for the key encryption.");

        internal static Command RequiredEncryptionPassword(this Command command)
              => Password(command, "The password for the key encryption.", isRequired: true);

        internal static Command DecryptionPassword(this Command command)
            => Password(command, "The password for the key decryption.");

        internal static Command RequiredDecryptionPassword(this Command command)
            => Password(command, "The password for the key decryption.", isRequired: true);

        internal static Command OptionalCertificatePassword(this Command command)
        {
            command.Add(new Option<string>("--certificate-password", "The password of the certificate.")
            {
                IsRequired = false
            });

            return command;
        }

        internal static Command Password(this Command command, string description, bool isRequired = false)
        {
            command.Add(new Option<string>(new[] { "-p", "--password" }, description)
            {
                IsRequired = isRequired
            });

            command.Add(new Option<int>("--iteration-count", "The iteration count used for the password derivation.")
                .Positive("The option --iteration-count must be a positive integer."));
            command.AddValidator(a => !a.Children.Contains("-p") && a.Children.Contains("--iteration-count") ? "The option --iteration-count must be used with the option -p." : null);

            command.Add(new Option<int>("--salt-size", "The salt size in bytes used for the password derivation.")
                .Positive("The option --salt-size must be a positive integer."));
            command.AddValidator(a => !a.Children.Contains("-p") && a.Children.Contains("--salt-size") ? "The option --salt-size must be used with the option -p." : null);

            return command;
        }

        internal static Command JwkParameters(this Command command)
        {
            command.Add(new Option<string>("--alg", $"The algorithm intended for use with the key. Supported algorithms are {string.Join(", ", GetSupportedAlgorithms(command.Name))}")
                .FromAmong(GetSupportedAlgorithms(command.Name)));
            command.Add(new Option<string>("--use", $"The public key intended use ({string.Join(", ", GetSupportedUse())}).")
                .FromAmong(GetSupportedUse()));
            command.Add(new Option<string>("--key-ops", $"The operation for which the key is intended to be used ({string.Join(", ", GetSupportedKeyOps())}).")
                .FromAmong(GetSupportedKeyOps()));
            command.Add(new Option<string>("--kid", "The key identifier."));
            command.Add(new Option("--no-kid", "Does not auto-generate a key identifier."));

            return command;
        }

        internal static Command Force(this Command command)
        {
            command.Add(new Option("--force", "Erase the output file whether it exist."));
            return command;
        }

        private static string[] GetSupportedAlgorithms(string keyType)
        {
            return keyType switch
            {
                "oct" => new[] {
                    SignatureAlgorithm.HS256,
                    SignatureAlgorithm.HS384,
                    SignatureAlgorithm.HS512,
                }.Select(a => a.Name.ToString())
                .Concat(new[] {
                    KeyManagementAlgorithm.A128KW,
                    KeyManagementAlgorithm.A192KW,
                    KeyManagementAlgorithm.A256KW,
                    KeyManagementAlgorithm.A128GcmKW,
                    KeyManagementAlgorithm.A192GcmKW,
                    KeyManagementAlgorithm.A256GcmKW,
                    KeyManagementAlgorithm.Dir,
                }.Select(a => a.Name.ToString())).ToArray(),
                "RSA" => new[] {
                    SignatureAlgorithm.RS256,
                    SignatureAlgorithm.RS384,
                    SignatureAlgorithm.RS512,
                    SignatureAlgorithm.PS256,
                    SignatureAlgorithm.PS384,
                    SignatureAlgorithm.PS512,
                }.Select(a => a.Name.ToString())
                .Concat(new[] {
                    KeyManagementAlgorithm.Rsa1_5,
                    KeyManagementAlgorithm.RsaOaep,
                    KeyManagementAlgorithm.RsaOaep256,
                    KeyManagementAlgorithm.RsaOaep384,
                    KeyManagementAlgorithm.RsaOaep512,
                }.Select(a => a.Name.ToString())).ToArray(),
                "EC" => new[] {
                    SignatureAlgorithm.ES256,
                    SignatureAlgorithm.ES384,
                    SignatureAlgorithm.ES512,
                }.Select(a => a.Name.ToString())
                .Concat(new[] {
                    KeyManagementAlgorithm.EcdhEs,
                    KeyManagementAlgorithm.EcdhEsA128KW,
                    KeyManagementAlgorithm.EcdhEsA192KW,
                    KeyManagementAlgorithm.EcdhEsA256KW,
                }.Select(a => a.Name.ToString())).ToArray(),
                _ => Array.Empty<string>()
            };
        }

        private static string[] GetSupportedUse()
        {
            return new[]
            {
                JwkUseValues.Sig.ToString(),
                JwkUseValues.Enc.ToString()
            };
        }

        private static string[] GetSupportedKeyOps()
        {
            return new[]
            {
                JwkKeyOpsValues.Sign.ToString(),
                JwkKeyOpsValues.Verify.ToString(),
                JwkKeyOpsValues.Encrypt.ToString(),
                JwkKeyOpsValues.Decrypt.ToString(),
                JwkKeyOpsValues.WrapKey.ToString(),
                JwkKeyOpsValues.UnwrapKey.ToString(),
                JwkKeyOpsValues.DeriveBits.ToString()
            };
        }

    }
}
