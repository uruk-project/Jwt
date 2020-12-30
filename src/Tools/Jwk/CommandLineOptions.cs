using Microsoft.Extensions.CommandLineUtils;

namespace JsonWebToken.Tools.Jwk
{
    public class CommandLineOptions
    {
        public ICommand? Command { get; set; }
        public bool IsHelp { get; private set; }
        public bool IsVerbose { get; private set; }

        public static CommandLineOptions? Parse(string[] args, IConsole console)
        {
            var app = new CommandLineApplication(throwOnUnexpectedArg: true)
            {
                Out = console.Out,
                Error = console.Error,
                Name = "dotnet jwk",
                FullName = "JWK manager",
                Description = "Manages JSON Web Keys"
            };

            app.HelpOption();
            app.VersionOptionFromAssemblyAttributes(typeof(Program).Assembly);

            var optionVerbose = app.VerboseOption();

            var options = new CommandLineOptions();

            app.Command("new", c => NewCommand.Configure(c, options));
            app.Command("decrypt", c => DecryptCommand.Configure(c, options));
            app.Command("encrypt", c => EncryptCommand.Configure(c, options));
            app.Command("convert", c => ConvertCommand.Configure(c, options));

            // Show help information if no subcommand/option was specified.
            app.OnExecute(() => app.ShowHelp());
            
            if (app.Execute(args) != 0)
            {
                // when command line parsing error in subcommand
                return null;
            }

            options.IsHelp = app.IsShowingInformation;
            options.IsVerbose = optionVerbose.HasValue();

            return options;
        }
    }
}
