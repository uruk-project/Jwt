using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    internal class NewCommand
    {
        internal static Command Create()
        {
            var command = new Command("new", "Creates a new JWK")
            {
                new Command("oct", "Creates a new JWK of type 'oct'")
                    {
                        Handler = CommandHandler.Create(typeof(NewSymmetricHandler).GetMethod(nameof(ICommandHandler.InvokeAsync), new [] { typeof(InvocationContext)})!)
                    }
                    .RequireKeyLength(8, 512, 8)
                    .OptionalOutputPath("The shared key output path.")
                    .OptionalEncryptionPassword()
                    .JwkParameters()
                    .Force()
                    .Verbose(),
                new Command("RSA", "Creates a new JWK of type 'RSA'")
                    {
                        Handler = CommandHandler.Create(typeof(NewRsaHandler).GetMethod(nameof(ICommandHandler.InvokeAsync), new [] { typeof(InvocationContext)})!)
                    }
                    .RequireKeyLength(0, 16384, 256)
                    .OptionalPrivateKeyOutputPath()
                    .OptionalPublicKeyOutputPath()
                    .OptionalEncryptionPassword()
                    .JwkParameters()
                    .Force()
                    .Verbose(),
                new Command("EC", "Creates a new JWK of type 'EC'")
                    {
                        Handler = CommandHandler.Create(typeof(NewECHandler).GetMethod(nameof(ICommandHandler.InvokeAsync), new [] { typeof(InvocationContext)})!)
                    }
                    .RequireCurve()
                    .OptionalPrivateKeyOutputPath()
                    .OptionalPublicKeyOutputPath()
                    .OptionalEncryptionPassword()
                    .JwkParameters()
                    .Force()
                    .Verbose(),
            };

            return command;
        }

        internal abstract class NewHandlerBase<TJwk> : ICommandHandler where TJwk : JsonWebToken.Jwk
        {
            protected readonly FileInfo? _outputPath;
            protected readonly FileInfo? _publicOutputPath;
            protected readonly string? _password;
            protected readonly uint _iterationCount;
            protected readonly uint _saltSize;
            protected readonly string? _alg;
            protected readonly string? _use;
            protected readonly List<string?> _keyOps;
            protected readonly string? _kid;
            protected readonly bool _noKid;
            protected readonly bool _force;
            protected readonly IStore _store;

            protected NewHandlerBase(FileInfo? outputPath, FileInfo? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force, IStore store)
            {
                _outputPath = outputPath;
                _publicOutputPath = publicOutputPath;
                _password = password;
                _iterationCount = iterationCount ?? 1000;
                _saltSize = saltSize ?? 8;
                _alg = alg;
                _use = use;
                _keyOps = keyOps;
                _kid = kid;
                _noKid = noKid;
                _force = force;
                _store = store;
            }

            public virtual Task<int> InvokeAsync(InvocationContext context)
                => InvokeAsync(context.Console);

            public abstract Task<int> InvokeAsync(IConsole console);

            protected abstract TJwk GenerateKey(IConsole console);

            protected string EncryptKey(IConsole console, JsonWebToken.Jwk key)
            {
                if (_password is null)
                {
                    return key.ToString();
                }

                var alg = KeyManagementAlgorithm.Pbes2HS256A128KW;
                var enc = EncryptionAlgorithm.A128CbcHS256;
                console.Verbose(
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
                console.Verbose("JWK encrypted.");
                return result;
            }
        }

        internal sealed class NewSymmetricHandler : NewHandlerBase<SymmetricJwk>
        {
            private readonly int _keyLength;

            public NewSymmetricHandler(FileInfo? outputPath, string? password, uint? iterationCount, uint? saltSize, int length, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force, IStore store)
                : base(outputPath, null, password, iterationCount, saltSize, alg, use, keyOps, kid, noKid, force, store)
            {
                _keyLength = length;
            }

            protected override SymmetricJwk GenerateKey(IConsole console)
            {
                SymmetricJwk key;
                var stopwatch = new Stopwatch();
                if (_keyLength != 0)
                {
                    console.Verbose($@"Generating 'oct' JWK of {_keyLength} bits...");
                    stopwatch.Start();
                    key = SymmetricJwk.GenerateKey(_keyLength, computeThumbprint: !_noKid);
                }
                else if (SignatureAlgorithm.TryParse(_alg, out var signatureAlgorithm))
                {
                    console.Verbose($@"Generating 'oct' JWK of {signatureAlgorithm.RequiredKeySizeInBits} bits for algorithm {signatureAlgorithm}...");
                    stopwatch.Start();
                    key = SymmetricJwk.GenerateKey(signatureAlgorithm, computeThumbprint: !_noKid);
                }
                else if (KeyManagementAlgorithm.TryParse(_alg, out var keyManagementAlgorithm))
                {
                    console.Verbose($@"Generating 'oct' JWK of {keyManagementAlgorithm.RequiredKeySizeInBits} bits for algorithm {signatureAlgorithm}...");
                    stopwatch.Start();
                    key = SymmetricJwk.GenerateKey(keyManagementAlgorithm, computeThumbprint: !_noKid);
                }
                else
                {
                    throw new InvalidOperationException("Unable to found the way to generate the key. Please specify a valid key length or a valid algorithm.");
                }

                console.Verbose($"JWK generated in {stopwatch.ElapsedMilliseconds} ms.");
                if (_kid != null)
                {
                    console.Verbose($"kid: {_kid}");
                    key.Kid = JsonEncodedText.Encode(_kid);
                }
                else if (!_noKid)
                {
                    console.Verbose($"kid: {key.Kid}");
                }

                if (_use != null)
                {
                    console.Verbose($"use: {_use}");
                    key.Use = JsonEncodedText.Encode(_use);
                }

                if (_keyOps != null && _keyOps.Count != 0)
                {
                    console.Verbose($"key_ops: {string.Join(", ", _keyOps)}");
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

            public override async Task<int> InvokeAsync(IConsole console)
            {
                var key = GenerateKey(console);
                string value = EncryptKey(console, key);
                if (_outputPath is null)
                {
                    console.Write(value);
                }
                else
                {
                    console.Verbose($"Writing JWK into file {_outputPath}...");
                    await _store.Write(_outputPath.FullName, value, _force);
                    console.Verbose("Done.");
                }

                return 0;
            }
            public override Task<int> InvokeAsync(InvocationContext context)
            {
                return base.InvokeAsync(context);
            }
        }

        internal abstract class NewAsymmetricHandler<TJwk> : NewHandlerBase<TJwk> where TJwk : AsymmetricJwk
        {
            protected NewAsymmetricHandler(FileInfo? outputPath, FileInfo? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force, IStore store)
                : base(outputPath, publicOutputPath, password, iterationCount, saltSize, alg, use, keyOps, kid, noKid, force, store)
            {
            }

            public async override Task<int> InvokeAsync(IConsole console)
            {
                var key = GenerateKey(console);
                string value = EncryptKey(console, key);
                if (_outputPath is null)
                {
                    console.Write(value);
                }
                else
                {
                    console.Verbose($"Writing private JWK into file {_outputPath}...");
                    await _store.Write(_outputPath.FullName, value, _force);
                    if (!(_publicOutputPath is null))
                    {
                        console.Verbose($"Writing public JWK into file {_outputPath}...");
                        await _store.Write(_publicOutputPath.FullName, key.AsPublicKey().ToString(), _force);
                    }

                    console.Verbose("Done.");
                }

                return 0;
            }

            public override Task<int> InvokeAsync(InvocationContext context)
            {
                return base.InvokeAsync(context);
            }
        }

        internal sealed class NewRsaHandler : NewAsymmetricHandler<RsaJwk>
        {
            private readonly int _keyLength;

            public NewRsaHandler(FileInfo? outputPath, FileInfo? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, int length, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force, IStore store)
                : base(outputPath, publicOutputPath, password, iterationCount, saltSize, alg, use, keyOps, kid, noKid, force, store)
            {
                _keyLength = length;
            }

            protected override RsaJwk GenerateKey(IConsole console)
            {
                RsaJwk key;
                var stopwatch = new Stopwatch();
                if (SignatureAlgorithm.TryParse(_alg, out var signatureAlgorithm))
                {
                    console.Verbose($@"Generating 'RSA' JWK of {_keyLength} bits for algorithm {signatureAlgorithm}...");
                    stopwatch.Start();
                    key = RsaJwk.GeneratePrivateKey(_keyLength, signatureAlgorithm, computeThumbprint: !_noKid);
                }
                else if (KeyManagementAlgorithm.TryParse(_alg, out var keyManagementAlgorithm))
                {
                    console.Verbose($@"Generating 'RSA' JWK of {_keyLength} bits for algorithm {keyManagementAlgorithm}...");
                    stopwatch.Start();
                    key = RsaJwk.GeneratePrivateKey(_keyLength, keyManagementAlgorithm, computeThumbprint: !_noKid);
                }
                else if (_keyLength != 0)
                {
                    console.Verbose($@"Generating 'RSA' JWK of {_keyLength} bits...");
                    stopwatch.Start();
                    key = RsaJwk.GeneratePrivateKey(_keyLength, computeThumbprint: !_noKid);
                }
                else
                {
                    throw new InvalidOperationException("Unable to found the way to generate the key. Please specify a valid key length or a valid algorithm.");
                }

                console.Verbose($"JWK generated in {stopwatch.ElapsedMilliseconds} ms.");
                if (_kid != null)
                {
                    console.Verbose($"kid: {_kid}");
                    key.Kid = JsonEncodedText.Encode(_kid);
                }
                else if (!_noKid)
                {
                    console.Verbose($"kid: {key.Kid}");
                }

                if (_use != null)
                {
                    console.Verbose($"use: {_use}");
                    key.Use = JsonEncodedText.Encode(_use);
                }

                if (_keyOps != null && _keyOps.Count != 0)
                {
                    console.Verbose($"key_ops: {string.Join(", ", _keyOps)}");
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

            public override Task<int> InvokeAsync(InvocationContext context)
            {
                return base.InvokeAsync(context);
            }
        }

        internal sealed class NewECHandler : NewAsymmetricHandler<ECJwk>
        {
            private readonly string _curve;

            public NewECHandler(FileInfo? outputPath, FileInfo? publicOutputPath, string? password, uint? iterationCount, uint? saltSize, string curve, string? alg, string? use, List<string?> keyOps, string? kid, bool noKid, bool force, IStore store)
                : base(outputPath, publicOutputPath, password, iterationCount, saltSize, alg, use, keyOps, kid, noKid, force, store)
            {
                _curve = curve;
            }

            public override Task<int> InvokeAsync(InvocationContext context)
            {
                return base.InvokeAsync(context);
            }

            protected override ECJwk GenerateKey(IConsole console)
            {
                ECJwk key;
                var stopwatch = new Stopwatch();
                if (SignatureAlgorithm.TryParse(_alg, out var signatureAlgorithm))
                {
                    if (EllipticalCurve.TryParse(_curve, out var curve))
                    {
                        if (EllipticalCurve.TryGetSupportedCurve(signatureAlgorithm, out var curve2))
                        {
                            if (curve.Id != curve2.Id)
                            {
                                throw new InvalidOperationException($@"Unable to generate 'EC' JWK. Curve '{curve}' and algorithm '{signatureAlgorithm}' are not compatible'. Use algorithm '{curve.SupportedSignatureAlgorithm}' with curve '{curve}', or curve '{curve2}' with algorithm '{signatureAlgorithm}'.");
                            }
                        }
                        else
                        {
                            throw new InvalidOperationException($@"Unable to generate 'EC' JWK. Curve '{curve}' and algorithm '{signatureAlgorithm}' are not compatible'. Use algorithm '{curve.SupportedSignatureAlgorithm}' with curve '{curve}'.");
                        }
                    }

                    console.Verbose($@"Generating 'EC' JWK of {signatureAlgorithm.RequiredKeySizeInBits} bits for algorithm {signatureAlgorithm}...");
                    stopwatch.Start();
                    key = ECJwk.GeneratePrivateKey(signatureAlgorithm, computeThumbprint: !_noKid);
                }
                else if (EllipticalCurve.TryParse(_curve, out var curve))
                {
                    if (KeyManagementAlgorithm.TryParse(_alg, out var keyManagementAlgorithm))
                    {
                        console.Verbose($@"Generating 'EC' JWK for algorithm {keyManagementAlgorithm} and curve {curve}...");
                        stopwatch.Start();
                        key = ECJwk.GeneratePrivateKey(curve, keyManagementAlgorithm, computeThumbprint: !_noKid);
                    }
                    else
                    {
                        console.Verbose($@"Generating 'EC' JWK for curve {curve}...");
                        stopwatch.Start();
                        key = ECJwk.GeneratePrivateKey(curve, computeThumbprint: !_noKid);
                    }
                }
                else
                {
                    throw new InvalidOperationException("Unable to found the way to generate the key. Please specify a valid curve or a valid algorithm.");
                }

                console.Verbose($"JWK generated in {stopwatch.ElapsedMilliseconds} ms.");
                if (_kid != null)
                {
                    console.Verbose($"kid: {_kid}");
                    key.Kid = JsonEncodedText.Encode(_kid);
                }
                else if (!_noKid)
                {
                    console.Verbose($"kid: {key.Kid}");
                }

                if (_use != null)
                {
                    console.Verbose($"use: {_use}");
                    key.Use = JsonEncodedText.Encode(_use);
                }

                if (_keyOps != null && _keyOps.Count != 0)
                {
                    console.Verbose($"key_ops: {string.Join(", ", _keyOps)}");
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
    }
}
