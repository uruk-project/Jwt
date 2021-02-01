using System.CommandLine;
using System.CommandLine.Parsing;

namespace JsonWebToken.Tools.Jwk
{
    internal static class OptionExtensions
    {
        internal static Option<int> KeyLength(this Option<int> option, int minValue, int maxValue, int modulo)
        {
            option.IsRequired = true;
            option.Range(minValue, maxValue, $"The -l option must be an integer between {minValue} and {maxValue}.");
            option.Argument.AddValidator(
             a => (a.GetValueOrDefault<int>() % modulo) == 0
                      ? null
                      : $"The -l option must be a multiple of 8.");

            return option;
        }

        internal static Option<int> Range(this Option<int> option, int minValue, int maxValue, string message)
        {
            option.Argument.AddValidator(a => a.GetValueOrDefault<int>() >= minValue && a.GetValueOrDefault<int>() <= maxValue
                        ? null
                        : message);

            return option;
        }

        internal static Option<int> Positive(this Option<int> option, string message)
        {
            option.Argument.AddValidator(a => a.GetValueOrDefault<int>() >= 0
                        ? null
                        : message);

            return option;
        }
    }
}
