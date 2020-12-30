using System;

namespace JsonWebToken.Tools.Jwk
{
    public abstract class TransformKeyCommand : ICommand
    {
        protected string? _value;
        protected string _password;
        protected readonly uint _iterationCount;
        protected readonly uint _saltSize;
        protected readonly string? _inputPath;
        protected string? _outputPath;
        private readonly bool _force;

        protected TransformKeyCommand(string? value, string password, uint? iterationCount, uint? saltSize, string? inputPath, string? outputPath, bool force)
        {
            _value = value;
            _password = password;
            _iterationCount = iterationCount ?? 1000;
            _saltSize = saltSize ?? 8;
            _inputPath = inputPath;
            _outputPath = outputPath;
            _force = force;
        }

        public void Execute(CommandContext context)
        {
            string value;
            if (!(_inputPath is null))
            {
                context.Reporter.Verbose($"Reading JWK from {_inputPath} file...");
                value = context.Store.Read(_inputPath);
                context.Reporter.Verbose("JWK successfully read.");
            }
            else if (_value != null)
            {
                value = _value;
            }
            else
            {
                throw new InvalidOperationException("No data to decrypt.");
            }

            var key = Transform(context, value);
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

        public abstract string Transform(CommandContext context, string data);
    }
}
