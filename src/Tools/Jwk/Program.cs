using System;
using Microsoft.Extensions.CommandLineUtils;

namespace JsonWebToken.Tools.Jwk
{
    public class Program
    {
        private readonly IConsole _console;

        public static int Main(string[] args)
        {
            DebugHelper.HandleDebugSwitch(ref args);

           return new Program(PhysicalConsole.Singleton).TryRun(args);
        }

        public Program(IConsole console)
        {
            _console = console;
        }

        public int TryRun(string[] args)
        {
            try
            {
                return Run(args);
            }
            catch (Exception exception)
            {
                var reporter = CreateReporter(verbose: true);
                reporter.Verbose(exception.ToString());
                reporter.Error(exception.Message);
                return 1;
            }
        }

        internal int Run(params string[] args)
        {
            CommandLineOptions? options;
            try
            {
                options = CommandLineOptions.Parse(args, _console);
            }
            catch (CommandParsingException ex)
            {
                CreateReporter(verbose: false).Error(ex.Message);
                return 1;
            }

            if (options == null)
            {
                return 1;
            }

            if (options.IsHelp)
            {
                return 2;
            }

            var reporter = CreateReporter(options.IsVerbose);
            var context = new CommandContext(new FileStore(), reporter, _console);
            options.Command?.Execute(context);
            return 0;
        }

        private IReporter CreateReporter(bool verbose)
            => new ConsoleReporter(_console, verbose, quiet: false);
    }
}
