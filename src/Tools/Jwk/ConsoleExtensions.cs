using System;
using System.CommandLine;
using System.CommandLine.IO;
using System.Linq;

namespace JsonWebToken.Tools.Jwk
{
    internal static partial class ConsoleExtensions
    {
        internal static void SetTerminalForeground(this IConsole console, ConsoleColor color)
        {
            if (console.GetType().GetInterfaces().Any(i => i.Name == "ITerminal"))
            {
                ((dynamic)console).ForegroundColor = color;
            }

            if (IsConsoleRedirectionCheckSupported &&
                !Console.IsOutputRedirected)
            {
                Console.ForegroundColor = color;
            }
            else if (IsConsoleRedirectionCheckSupported)
            {
                Console.ForegroundColor = color;
            }
        }

        internal static void ResetColor(this IConsole console)
        {
            if (console.GetType().GetInterfaces().Any(i => i.Name == "ITerminal"))
            {
                ((dynamic)console).ForegroundColor = ConsoleColor.Gray;
            }

            if (IsConsoleRedirectionCheckSupported &&
                !Console.IsOutputRedirected)
            {
                Console.ResetColor();
            }
            else if (IsConsoleRedirectionCheckSupported)
            {
                Console.ResetColor();
            }
        }

        private static bool? _isConsoleRedirectionCheckSupported;

        public static bool IsConsoleRedirectionCheckSupported
        {
            get
            {
                if (_isConsoleRedirectionCheckSupported is null)
                {
                    try
                    {
                        var check = Console.IsOutputRedirected;
                        _isConsoleRedirectionCheckSupported = true;
                    }

                    catch (PlatformNotSupportedException)
                    {
                        _isConsoleRedirectionCheckSupported = false;
                    }
                }

                return _isConsoleRedirectionCheckSupported.Value;
            }
        }
        private static readonly object _writeLock = new object();

        internal static bool IsVerbose { get; set; }

        private static void WriteLine(this IConsole console, IStandardStreamWriter writer, string message, ConsoleColor? color)
        {
            lock (_writeLock)
            {
                if (color.HasValue)
                {
                    console.SetTerminalForeground(color.Value);
                }

                writer.WriteLine(message);

                if (color.HasValue)
                {
                    console.ResetColor();
                }
            }
        }

        public static void Error(this IConsole console, string message)
            => console.WriteLine(console.Error, message, ConsoleColor.Red);

        public static void Warn(this IConsole console, string message)
            => console.WriteLine(console.Out, message, ConsoleColor.Yellow);

        public static void Write(this IConsole console, string message)
            => console.Out.WriteLine(message);

        public static void Verbose(this IConsole console, string message)
        {
            if (!IsVerbose)
            {
                return;
            }

            console.WriteLine(console.Out, message, ConsoleColor.DarkGray);
        }
    }
}
