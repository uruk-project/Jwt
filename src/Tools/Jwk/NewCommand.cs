using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using JsonWebToken.Cryptography;
using Microsoft.Extensions.CommandLineUtils;

namespace JsonWebToken.Tools.Jwk
{
    internal class NewCommand
    {
        public static void Configure(CommandLineApplication command, CommandLineOptions options)
        {
            command.Description = "Creates a new JWK";
            command.ExtendedHelpText =
@"Examples:
  dotnet jwk new -kty oct -l 128 -o ./symmetric_key.jwk
  dotnet jwk new -kty RSA -l 4096 -o ./rsa_key.jwk
  dotnet jwk new -kty EC -c P-521 -o ./ec_key.jwk
  dotnet jwk new -kty oct -l 128 -p <password> -o ./encrypted_symmetric_key.jwk
  dotnet jwk new -kty oct -l 128 -o ./symmetric_key.jwk --alg HS256
  dotnet jwk new -kty RSA -l 4096 -o ./rsa_key.jwk --alg RS256 --use sign
";

            command.HelpOption();

            var keyTypeOption = command.Option("-kty|--key-type <KEY_TYPE>", "Type of the key (oct, RSA or EC).", CommandOptionType.SingleValue);
            var keyLengthOption = command.Option("-l|--length <LENGTH>", "Length in bits of the key. Only for 'oct' and 'RSA' key.", CommandOptionType.SingleValue);
            var curveOption = command.Option("-c|--curve <CURVE>", "The elliptical curve. Only for 'EC' key.", CommandOptionType.SingleValue);
            var outputPathOption = command.Option("-o|--output-path <OUTPUT_PATH>", "The private key output path.", CommandOptionType.SingleValue);
            var publicOutputPathOption = command.Option("--public-output-path <PUBLIC_OUTPUT_PATH>", "The public key output path. Only for 'RSA' and 'EC' key.", CommandOptionType.SingleValue);
            var passwordOption = command.Option("-p|--password <PASSWORD>", "The password used to encrypt the key.", CommandOptionType.SingleValue);
            var iterationCountOption = command.Option("--iteration-count <ITERATION_COUNT>", "The iteration count used for the password derivation.", CommandOptionType.SingleValue);
            var saltSizeOption = command.Option("--salt-size <SALT_SIZE>", "The salt size in bytes used for the password derivation.", CommandOptionType.SingleValue);
            var algOption = command.Option("--alg <ALGORITHM>", $"The algorithm intended for use with the key. Supported algorithms are {string.Join(", ", GetSupportedAlgorithms())}", CommandOptionType.SingleValue);
            var usageOption = command.Option("--use <USAGE>", $"The public key intended use ({string.Join(", ", GetSupportedUse())}).", CommandOptionType.SingleValue);
            var keyOpsOption = command.Option("--key-ops <KEY_OPS>", $"The operation for which the key is intended to be used ({string.Join(", ", GetSupportedKeyOps())}).", CommandOptionType.MultipleValue);
            var kidOption = command.Option("--kid <KEY_IDENTIFIER>", "The key identifier.", CommandOptionType.SingleValue);
            var noKidOption = command.Option("--no-kid", "Does not auto-generate a key identifier.", CommandOptionType.NoValue);
            var forceOption = command.Option("--force", "Erase the output file whether it exist.", CommandOptionType.NoValue);

            command.OnExecute(() =>
            {
                if (!keyTypeOption.HasValue())
                {
                    throw new CommandParsingException(command, "Missing option -kty.");
                }

                int keyLength = 0;
                if (!keyLengthOption.HasValue())
                {
                    if (keyTypeOption.Value() == "oct")
                    {
                        throw new CommandParsingException(command, "Missing option -l: Valid value for 'oct' key is an integer between 128 and 512 and be a multiple of 8.");
                    }
                    else if (keyTypeOption.Value() == "RSA")
                    {
                        throw new CommandParsingException(command, "Missing option -l: Valid value for 'RSA' key is an integer between 512 and 16384 and be a multiple of 8.");
                    }
                }
                else if (keyTypeOption.Value() == "oct" || keyTypeOption.Value() == "RSA")
                {
                    if (!int.TryParse(keyLengthOption.Value(), out keyLength))
                    {
                        throw new CommandParsingException(command, "Invalid option -l. Valid value is an integer between 0 and 16384.");
                    }
                }

                switch (keyTypeOption.Value())
                {
                    case "oct" when keyLength < 128 && keyLength > 512:
                        throw new CommandParsingException(command, "Invalid option -l: Valid value for 'oct' key is an integer between 128 and 512 and be a multiple of 8.");
                    case "RSA" when keyLength < 512 && keyLength > 16384:
                        throw new CommandParsingException(command, "Invalid option -l: Valid value for 'RSA' key is an integer between 512 and 16384 and be a multiple of 8.");
                    case "EC" when !curveOption.HasValue():
                        throw new CommandParsingException(command, "Missing option -c: Valid values are 'P-256', 'P-384', 'P-521' and 'secp256k1'.");
                    case "EC":
                        switch (curveOption.Value())
                        {
                            case "P-256":
                            case "P-384":
                            case "P-521":
                            case "secp256k1":
                                break;
                            default:
                                throw new CommandParsingException(command, "Invalid option -c: Valid values are 'P-256', 'P-384', 'P-521' and 'secp256k1'.");
                        }
                        break;
                    case "oct" when publicOutputPathOption.HasValue():
                        throw new CommandParsingException(command, "Invalid option --public-output-path: 'oct' key does not have public key.");

                    case "oct":
                    case "RSA":
                        if ((keyLength & 7) != 0)
                        {
                            throw new CommandParsingException(command, "Invalid option -l. Valid value for 'oct' or 'RSA' key is an integer between 0 and 16384 and be a multiple of 8.");
                        }
                        break;
                    default:
                        throw new CommandParsingException(command, "Invalid option -kty: Valid values are 'oct', 'RSA' and 'EC'.");
                }

                if (iterationCountOption.HasValue() && !passwordOption.HasValue())
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

                if (saltSizeOption.HasValue() && !passwordOption.HasValue())
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

                SignatureAlgorithm? signatureAlgorithm = null;
                KeyManagementAlgorithm? keyManagementAlgorithm = null;
                if (algOption.HasValue()
                    && !SignatureAlgorithm.TryParse(algOption.Value(), out signatureAlgorithm)
                    && !KeyManagementAlgorithm.TryParse(algOption.Value(), out keyManagementAlgorithm))
                {
                    throw new CommandParsingException(command, "Invalid option --alg: The specified value is not supported.");
                }

                if (!(signatureAlgorithm is null) && curveOption.HasValue()
                    && EllipticalCurve.TryParse(curveOption.Value(), out var curve) && curve.KeySizeInBits != signatureAlgorithm.RequiredKeySizeInBits)
                {
                    throw new CommandParsingException(command, "Invalid options --alg and -c: The specified value are not compatible.");
                }

                AlgorithmCategory category = signatureAlgorithm is null ? keyManagementAlgorithm is null ? AlgorithmCategory.None : keyManagementAlgorithm.Category : signatureAlgorithm.Category;
                switch (category)
                {
                    case AlgorithmCategory.EllipticCurve when keyTypeOption.Value() != "EC":
                        throw new CommandParsingException(command, "Invalid options --kty and -alg: The specified value are not compatible. Use an 'EC' key for an EC algorithm.");
                    case AlgorithmCategory.Rsa when keyTypeOption.Value() != "RSA":
                        throw new CommandParsingException(command, "Invalid options --kty and -alg: The specified value are not compatible. Use a 'RSA' key for an RSA algorithm.");
                    case AlgorithmCategory.Hmac when keyTypeOption.Value() != "oct":
                        throw new CommandParsingException(command, "Invalid options --kty and -alg: The specified value are not compatible. Use a 'oct' key for a symmetric algorithm.");
                    default:
                        break;
                }

                if (usageOption.HasValue() && !GetSupportedUse().Contains(usageOption.Value()))
                {
                    throw new CommandParsingException(command, "Invalid option --use: The specified value is not supported.");
                }

                if (keyOpsOption.HasValue())
                {
                    foreach (var keyOps in keyOpsOption.Values)
                    {
                        if (!GetSupportedKeyOps().Contains(keyOps))
                        {
                            throw new CommandParsingException(command, "Invalid option --key-ops: The specified value(s) is not supported.");
                        }
                    }
                }

                if (noKidOption.HasValue() && kidOption.HasValue())
                {
                    throw new CommandParsingException(command, "Invalid options --kid and --no-kid: The options can not be used together.");
                }

                options.Command = keyTypeOption.Value() switch
                {
                    "oct" => new SymmetricNewCommand(outputPathOption.Value(), passwordOption.Value(), iterationCount, saltSize, keyLength, algOption.Value(), usageOption.Value(), keyOpsOption.Values, kidOption.Value(), noKidOption.HasValue(), forceOption.HasValue()),
                    "RSA" => new RsaNewCommand(outputPathOption.Value(), publicOutputPathOption.Value(), passwordOption.Value(), iterationCount, saltSize, keyLength, algOption.Value(), usageOption.Value(), keyOpsOption.Values, kidOption.Value(), noKidOption.HasValue(), forceOption.HasValue()),
                    "EC" => new ECNewCommand(outputPathOption.Value(), publicOutputPathOption.Value(), passwordOption.Value(), iterationCount, saltSize, curveOption.Value(), algOption.Value(), usageOption.Value(), keyOpsOption.Values, kidOption.Value(), noKidOption.HasValue(), forceOption.HasValue()),
                    _ => throw new CommandParsingException(command, "Invalid key type.")
                };
            });
        }

        private abstract class NewCommandBase<TJwk> : ICommand where TJwk : JsonWebToken.Jwk
        {
            protected readonly string? _outputPath;
            protected readonly string? _publicOutputPath;
            protected readonly string? _password;
            protected readonly uint _iterationCount;
            protected readonly uint _saltSize;
            protected readonly int _keyLength;
            protected readonly string? _alg;
            protected readonly string? _use;
            protected readonly List<string?> _keyOps;
            protected readonly string? _kid;
            protected readonly bool _noKid;
            protected readonly bool _force;

            protected NewCommandBase(string? outputPath, string? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, int keyLength, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force)
            {
                _outputPath = outputPath;
                _publicOutputPath = publicOutputPath;
                _password = password;
                _iterationCount = iterationCount ?? 1000;
                _saltSize = saltSize ?? 8;
                _keyLength = keyLength;
                _alg = alg;
                _use = use;
                _keyOps = keyOps;
                _kid = kid;
                _noKid = noKid;
                _force = force;
            }

            public abstract void Execute(CommandContext context);

            protected abstract TJwk GenerateKey(CommandContext context);

            protected string EncryptKey(CommandContext context, JsonWebToken.Jwk key)
            {
                if (_password is null)
                {
                    return key.ToString();
                }

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
                var descriptor = new JwkJweDescriptor(encryptionKey, alg, enc)
                {
                    Payload = key
                };
                var result = writer.WriteTokenString(descriptor);
                context.Reporter.Verbose("JWK encrypted.");
                return result;
            }
        }

        private sealed class SymmetricNewCommand : NewCommandBase<SymmetricJwk>
        {
            public SymmetricNewCommand(string? outputPath, string? password, uint? iterationCount, uint? saltSize, int keyLength, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force)
                : base(outputPath, null, password, iterationCount, saltSize, keyLength, alg, use, keyOps, kid, noKid, force)
            {
            }

            protected override SymmetricJwk GenerateKey(CommandContext context)
            {
                SymmetricJwk key;
                if (_keyLength != 0)
                {
                    context.Reporter.Verbose($@"Generating 'oct' JWK of {_keyLength} bits...");
                    key = SymmetricJwk.GenerateKey(_keyLength, computeThumbprint: !_noKid);
                }
                else if (SignatureAlgorithm.TryParse(_alg, out var signatureAlgorithm))
                {
                    context.Reporter.Verbose($@"Generating 'oct' JWK of {signatureAlgorithm.RequiredKeySizeInBits} bits for algorithm {signatureAlgorithm}...");
                    key = SymmetricJwk.GenerateKey(signatureAlgorithm, computeThumbprint: !_noKid);
                }
                else if (KeyManagementAlgorithm.TryParse(_alg, out var keyManagementAlgorithm))
                {
                    context.Reporter.Verbose($@"Generating 'oct' JWK of {keyManagementAlgorithm.RequiredKeySizeInBits} bits for algorithm {signatureAlgorithm}...");
                    key = SymmetricJwk.GenerateKey(keyManagementAlgorithm, computeThumbprint: !_noKid);
                }
                else
                {
                    throw new InvalidOperationException("Unable to found the way to generate the key. Please specify a valid key length or a valid algorithm.");
                }

                if (_kid != null)
                {
                    context.Reporter.Verbose($"kid: {_kid}");
                    key.Kid = JsonEncodedText.Encode(_kid);
                }
                else if (!_noKid)
                {
                    context.Reporter.Verbose($"kid: {key.Kid}");
                }

                if (_use != null)
                {
                    context.Reporter.Verbose($"use: {_use}");
                    key.Use = JsonEncodedText.Encode(_use);
                }

                if (_keyOps != null && _keyOps.Count != 0)
                {
                    context.Reporter.Verbose($"key_ops: {string.Join(", ", _keyOps)}");
                    foreach (var keyOps in _keyOps)
                    {
                        if (keyOps != null)
                        {
                            key.KeyOps.Add(JsonEncodedText.Encode(keyOps));
                        }
                    }
                }

                return key;
            }

            public override void Execute(CommandContext context)
            {
                var key = GenerateKey(context);
                string value = EncryptKey(context, key);
                if (_outputPath is null)
                {
                    context.Console.Out.Write(value);
                }
                else
                {
                    context.Reporter.Verbose($"Writing JWK into file {_outputPath}...");
                    context.Store.Write(_outputPath, value, _force);
                    context.Reporter.Verbose("Done.");
                }
            }
        }

        private abstract class AsymmetricNewCommand<TJwk> : NewCommandBase<TJwk> where TJwk : AsymmetricJwk
        {
            protected AsymmetricNewCommand(string? outputPath, string? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, int keyLength, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force)
                : base(outputPath, publicOutputPath, password, iterationCount, saltSize, keyLength, alg, use, keyOps, kid, noKid, force)
            {
            }

            public override void Execute(CommandContext context)
            {
                var key = GenerateKey(context);
                string value = EncryptKey(context, key);
                if (_outputPath is null)
                {
                    context.Console.Out.Write(value);
                }
                else
                {
                    context.Reporter.Verbose($"Writing private JWK into file {_outputPath}...");
                    context.Store.Write(_outputPath, value, _force);
                    if (!(_publicOutputPath is null))
                    {
                        context.Reporter.Verbose($"Writing public JWK into file {_outputPath}...");
                        context.Store.Write(_publicOutputPath, key.AsPublicKey().ToString(), _force);
                    }
                    context.Reporter.Verbose("Done.");
                }
            }
        }

        private sealed class RsaNewCommand : AsymmetricNewCommand<RsaJwk>
        {
            public RsaNewCommand(string? outputPath, string? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, int keyLength, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force)
                : base(outputPath, publicOutputPath, password, iterationCount, saltSize, keyLength, alg, use, keyOps, kid, noKid, force)
            {
            }

            protected override RsaJwk GenerateKey(CommandContext context)
            {
                RsaJwk key;
                if (SignatureAlgorithm.TryParse(_alg, out var signatureAlgorithm))
                {
                    context.Reporter.Verbose($@"Generating 'RSA' JWK of {_keyLength} bits for algorithm {signatureAlgorithm}...");
                    key = RsaJwk.GeneratePrivateKey(_keyLength, signatureAlgorithm, computeThumbprint: !_noKid);
                }
                else if (KeyManagementAlgorithm.TryParse(_alg, out var keyManagementAlgorithm))
                {
                    context.Reporter.Verbose($@"Generating 'RSA' JWK of {_keyLength} bits for algorithm {keyManagementAlgorithm}...");
                    key = RsaJwk.GeneratePrivateKey(_keyLength, keyManagementAlgorithm, computeThumbprint: !_noKid);
                }
                else if (_keyLength != 0)
                {
                    context.Reporter.Verbose($@"Generating 'RSA' JWK of {_keyLength} bits...");
                    key = RsaJwk.GeneratePrivateKey(_keyLength, computeThumbprint: !_noKid);
                }
                else
                {
                    throw new InvalidOperationException("Unable to found the way to generate the key. Please specify a valid key length or a valid algorithm.");
                }

                if (_kid != null)
                {
                    context.Reporter.Verbose($"kid: {_kid}");
                    key.Kid = JsonEncodedText.Encode(_kid);
                }
                else if (!_noKid)
                {
                    context.Reporter.Verbose($"kid: {key.Kid}");
                }

                if (_use != null)
                {
                    context.Reporter.Verbose($"use: {_use}");
                    key.Use = JsonEncodedText.Encode(_use);
                }

                if (_keyOps != null && _keyOps.Count != 0)
                {
                    context.Reporter.Verbose($"key_ops: {string.Join(", ", _keyOps)}");
                    foreach (var keyOps in _keyOps)
                    {
                        if (keyOps != null)
                        {
                            key.KeyOps.Add(JsonEncodedText.Encode(keyOps));
                        }
                    }
                }

                return key;
            }
        }

        private sealed class ECNewCommand : AsymmetricNewCommand<ECJwk>
        {
            private readonly string _curve;

            public ECNewCommand(string? outputPath, string? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, string curve, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force)
                : base(outputPath, publicOutputPath, password, iterationCount, saltSize, 0, alg, use, keyOps, kid, noKid, force)
            {
                _curve = curve;
            }

            protected override ECJwk GenerateKey(CommandContext context)
            {
                ECJwk key;
                if (SignatureAlgorithm.TryParse(_alg, out var signatureAlgorithm))
                {
                    context.Reporter.Verbose($@"Generating 'EC' JWK of {signatureAlgorithm.RequiredKeySizeInBits} bits for algorithm {signatureAlgorithm}...");
                    key = ECJwk.GeneratePrivateKey(signatureAlgorithm, computeThumbprint: !_noKid);
                }
                else if (EllipticalCurve.TryParse(_curve, out var curve))
                {
                    if (KeyManagementAlgorithm.TryParse(_alg, out var keyManagementAlgorithm))
                    {
                        context.Reporter.Verbose($@"Generating 'EC' JWK for algorithm {keyManagementAlgorithm} and curve {curve}...");
                        key = ECJwk.GeneratePrivateKey(curve, keyManagementAlgorithm, computeThumbprint: !_noKid);
                    }
                    else
                    {
                        context.Reporter.Verbose($@"Generating 'EC' JWK for curve {curve}...");
                        key = ECJwk.GeneratePrivateKey(curve, computeThumbprint: !_noKid);
                    }
                }
                else
                {
                    throw new InvalidOperationException("Unable to found the way to generate the key. Please specify a valid curve or a valid algorithm.");
                }

                if (_kid != null)
                {
                    context.Reporter.Verbose($"kid: {_kid}");
                    key.Kid = JsonEncodedText.Encode(_kid);
                }
                else if (!_noKid)
                {
                    context.Reporter.Verbose($"kid: {key.Kid}");
                }

                if (_use != null)
                {
                    context.Reporter.Verbose($"use: {_use}");
                    key.Use = JsonEncodedText.Encode(_use);
                }

                if (_keyOps != null && _keyOps.Count != 0)
                {
                    context.Reporter.Verbose($"key_ops: {string.Join(", ", _keyOps)}");
                    foreach (var keyOps in _keyOps)
                    {
                        if (keyOps != null)
                        {
                            key.KeyOps.Add(JsonEncodedText.Encode(keyOps));
                        }
                    }
                }

                return key;
            }
        }

        private static string[] GetSupportedAlgorithms()
        {
            return
                SignatureAlgorithm.SupportedAlgorithms.Where(a => a != SignatureAlgorithm.None).Select(a => a.Name.ToString())
                .Concat(KeyManagementAlgorithm.SupportedAlgorithms.Where(a => a.Category != AlgorithmCategory.Pbkdf2).Select(a => a.Name.ToString())).ToArray();
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
