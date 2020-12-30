namespace JsonWebToken.Tools.Jwk
{
    /// <summary>
    /// This API supports infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public class CommandContext
    {
        public CommandContext(IStore store, IReporter reporter, IConsole console)
        {
            Store = store;
            Reporter = reporter;
            Console = console;
        }

        public IStore Store { get; }
        public IConsole Console { get; }
        public IReporter Reporter { get; }
    }
}
