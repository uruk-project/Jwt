using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    internal abstract class ConvertCommand : ICommandHandler
    {
        internal static Command Create()
        {
            var command = new Command("convert", "Convert a key to JWK format")
            {
                new Command("X509", "Convert a X509 file certificate to JWK format")
                {
                    Handler = CommandHandler.Create(typeof(ConvertX509Command).GetMethod(nameof(ICommandHandler.InvokeAsync))!)
                }
                .RequiredInputPath()
                .OptionalPrivateKeyOutputPath()
                .OptionalPublicKeyOutputPath()
                .OptionalCertificatePassword()
                .OptionalEncryptionPassword()
                .Force()
                .Verbose(),

                new Command("PEM", "Convert a PEM key file to JWK format")
                {
                    Handler = CommandHandler.Create(typeof(ConvertPemCommand).GetMethod(nameof(ICommandHandler.InvokeAsync))!)
                }
                .RequiredInputPath()
                .OptionalPrivateKeyOutputPath()
                .OptionalPublicKeyOutputPath()
                .OptionalEncryptionPassword()
                .Force()
                .Verbose()
            };

            return command;
        }

        private readonly string? _password;
        private readonly uint _iterationCount;
        private readonly uint _saltSize;
        protected FileInfo _inputPath;
        private FileInfo? _outputPath;
        private readonly bool _force;
        protected readonly IStore _store;

        public ConvertCommand(string? password, uint? iterationCount, uint? saltSize, FileInfo inputPath, FileInfo? outputPath, bool force, IStore store)
        {
            _password = password;
            _iterationCount = iterationCount ?? 1000;
            _saltSize = saltSize ?? 8;
            _inputPath = inputPath;
            _outputPath = outputPath;
            _force = force;
            _store = store;
        }

        public virtual Task<int> InvokeAsync(InvocationContext context)
            => InvokeAsync(context.Console);

        internal async Task<int> InvokeAsync(IConsole console)
        {
            string key = await Read(console);
            key = Transform(console, key);
            if (_outputPath is null)
            {
                console.Write(key);
            }
            else
            {
                console.Verbose($"Writing JWK into file {_outputPath}.");
                await _store.Write(_outputPath.FullName, key, _force);
                console.Verbose("Done.");
            }

            return 0;
        }

        public string Transform(IConsole console, string data)
        {
            if (_password != null)
            {
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
                var descriptor = new PlaintextJweDescriptor(encryptionKey, alg, enc)
                {
                    Payload = data
                };

                console.Verbose("JWK encrypted.");
                return writer.WriteTokenString(descriptor);
            }

            return data;
        }

        protected abstract Task<string> Read(IConsole console);
    }

    internal sealed class ConvertPemCommand : ConvertCommand
    {
        public ConvertPemCommand(string? password, uint? iterationCount, uint? saltSize, FileInfo inputPath, FileInfo? outputPath, bool force, IStore store)
            : base(password, iterationCount, saltSize, inputPath, outputPath, force, store)
        {
        }

        protected async override Task<string> Read(IConsole console)
        {
            console.Verbose($"Reading PEM key from {_inputPath} file...");
            string pem = await _store.Read(_inputPath.FullName);
            var key = JsonWebToken.Jwk.FromPem(pem);
            console.Verbose("PEM key successfully read.");
            return key.ToString();
        }

        public override Task<int> InvokeAsync(InvocationContext context)
        {
            return base.InvokeAsync(context);
        }
    }

    internal sealed class ConvertX509Command : ConvertCommand
    {
        private readonly string? _certificatePassword;

        public ConvertX509Command(string? certificatePassword, string? password, uint? iterationCount, uint? saltSize, FileInfo inputPath, FileInfo? outputPath, bool force, IStore store)
            : base(password, iterationCount, saltSize, inputPath, outputPath, force, store)
        {
            _certificatePassword = certificatePassword;
        }

        protected async  override Task<string> Read(IConsole console)
        {
            console.Verbose($"Reading X509 certificate from {_inputPath} file...");
            X509Certificate2 certificate = await _store.LoadX509(_inputPath.FullName, _certificatePassword);
            if (!JsonWebToken.Jwk.TryReadPrivateKeyFromX509Certificate(certificate, out AsymmetricJwk? key))
            {
                console.Verbose("No private key found. Reading X509 public key...");
                if (!JsonWebToken.Jwk.TryReadPublicKeyFromX509Certificate(certificate, out key))
                {
                    string? algorithm = Oid.FromOidValue(certificate.GetKeyAlgorithm(), OidGroup.All).FriendlyName;
                    throw new InvalidOperationException($"Unable to find a key the certificate. The certificate is for the algorithm '{algorithm}'.");
                }
            }

            console.Verbose("X509 certificate successfully read.");
            return key.ToString();
        }

        public override Task<int> InvokeAsync(InvocationContext context)
        {
            return base.InvokeAsync(context);
        }
    }
}
