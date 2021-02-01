using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Threading.Tasks;

namespace JsonWebToken.Tools.Jwk
{
    public abstract class TransformKeyCommand : ICommandHandler
    {
        protected string? _key;
        protected string _password;
        protected readonly uint _iterationCount;
        protected readonly uint _saltSize;
        protected readonly FileInfo? _inputPath;
        protected FileInfo? _outputPath;
        private readonly bool _force;
        private readonly IStore _store;

        protected TransformKeyCommand(string? key, string password, uint? iterationCount, uint? saltSize, FileInfo? inputPath, FileInfo? outputPath, bool force, IStore store)
        {
            _key = key;
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
            string value;
            if (!(_inputPath is null))
            {
                console.Verbose($"Reading JWK from {_inputPath} file...");
                value = await _store.Read(_inputPath.FullName);
                console.Verbose("JWK successfully read.");
            }
            else if (_key != null)
            {
                value = _key;
            }
            else
            {
                throw new InvalidOperationException("No data to decrypt.");
            }

            var key = Transform(console, value);
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

        public abstract string Transform(IConsole console, string data);
    }
}
