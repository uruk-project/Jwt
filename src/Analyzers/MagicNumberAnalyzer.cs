using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace JsonWebToken.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class MagicNumberAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "JWT0001";

        private static readonly LocalizableString Title = new LocalizableResourceString(nameof(Resources.AnalyzerTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormat = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString Description = new LocalizableResourceString(nameof(Resources.AnalyzerDescription), Resources.ResourceManager, typeof(Resources));
        private const string Category = "Naming";

        private static readonly DiagnosticDescriptor Rule = new DiagnosticDescriptor(DiagnosticId, Title, MessageFormat, Category, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: Description);
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics );
            context.EnableConcurrentExecution();

            context.RegisterSymbolAction(AnalyzeSymbol, SymbolKind.Field);
        }

        private void AnalyzeSymbol(SymbolAnalysisContext context)
        {
            var attributes = context.Symbol.GetAttributes();
            if (attributes.Length == 0)
            {
                return;
            }

            var attribute = attributes[0];
            if (!Equals(attribute.AttributeClass.Name, "MagicNumberAttribute"))
            {
                return;
            }

            var originalStringValue = (string)attribute.ConstructorArguments[0].Value;
            var stringValue = originalStringValue;
            var numericValue = ((IFieldSymbol)context.Symbol).ConstantValue;
            var numericType = ((IFieldSymbol)context.Symbol).Type;
            bool valid;
            string type = string.Empty;
            string possibleFix = string.Empty;
            ulong possibleNumericFix = 0;
            if (numericType.Name == typeof(ushort).Name)
            {
                type = typeof(ushort).Name;
                if (stringValue.Length < sizeof(ushort))
                {
                    stringValue = stringValue.PadRight(sizeof(ushort), '\0');
                }

                possibleNumericFix = BitConverter.ToUInt16(Encoding.UTF8.GetBytes(stringValue), 0);
                possibleFix = Encoding.UTF8.GetString(BitConverter.GetBytes((ushort)numericValue));
                valid = (ushort)numericValue == possibleNumericFix;
            }
            else if (numericType.Name == typeof(uint).Name)
            {
                type = typeof(uint).Name;
                if (stringValue.Length < sizeof(uint))
                {
                    stringValue = stringValue.PadRight(sizeof(uint), '\0');
                }

                possibleNumericFix = BitConverter.ToUInt32(Encoding.UTF8.GetBytes(stringValue), 0);
                possibleFix = Encoding.UTF8.GetString(BitConverter.GetBytes((uint)numericValue));
                valid = (uint)numericValue == possibleNumericFix;
            }
            else if (numericType.Name == typeof(ulong).Name)
            {
                type = typeof(ulong).Name;
                if (stringValue.Length < sizeof(ulong))
                {
                    stringValue = stringValue.PadRight(sizeof(ulong), '\0');
                }

                possibleNumericFix = BitConverter.ToUInt64(Encoding.UTF8.GetBytes(stringValue), 0);
                possibleFix = Encoding.UTF8.GetString(BitConverter.GetBytes((ulong)numericValue));
                valid = (ulong)numericValue == possibleNumericFix;
            }
            else
            {
                valid = true;
            }

            if (!valid)
            {
                var properties = new Dictionary<string, string> {
                    { "type", type },
                    { "stringValue", originalStringValue },
                    { "numericValue", numericValue.ToString() }
                }.ToImmutableDictionary();

                var diagnotic = Diagnostic.Create(Rule, context.Symbol.Locations.First(), properties, numericValue, originalStringValue.Trim('\0'), possibleFix.Trim('\0'), possibleNumericFix);
                context.ReportDiagnostic(diagnotic);
            }
        }
    }
}
