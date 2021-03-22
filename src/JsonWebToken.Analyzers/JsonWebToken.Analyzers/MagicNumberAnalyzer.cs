using System;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace JsonWebToken.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class MagicNumberAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "MagicNumberAnalyzer";

        // You can change these strings in the Resources.resx file. If you do not want your analyzer to be localize-able, you can use regular strings for Title and MessageFormat.
        // See https://github.com/dotnet/roslyn/blob/master/docs/analyzers/Localizing%20Analyzers.md for more on localization
        private static readonly LocalizableString Title = new LocalizableResourceString(nameof(Resources.AnalyzerTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormat = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString Description = new LocalizableResourceString(nameof(Resources.AnalyzerDescription), Resources.ResourceManager, typeof(Resources));
        private const string Category = "Naming";

        private static readonly DiagnosticDescriptor Rule = new DiagnosticDescriptor(DiagnosticId, Title, MessageFormat, Category, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: Description);
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            //context.EnableConcurrentExecution();

            // TODO: Consider registering other actions that act on syntax instead of or in addition to symbols
            // See https://github.com/dotnet/roslyn/blob/master/docs/analyzers/Analyzer%20Actions%20Semantics.md for more information
            context.RegisterSymbolAction(AnalyzeSymbol, SymbolKind.Field);
        }

        private void AnalyzeSymbol(SymbolAnalysisContext context)
        {
            var attributes = context.Symbol.GetAttributes();
            var attribute = attributes[0];
            if (!Equals(attribute.AttributeClass.Name, "MagicNumberAttribute"))
                return;

            var stringValue = (string)attribute.ConstructorArguments[0].Value;
            var numericValue = ((IFieldSymbol)context.Symbol).ConstantValue;
            var numericType = ((IFieldSymbol)context.Symbol).Type;
            bool valid;
            if (numericType.Name == typeof(ushort).Name)
            {
                valid = AssertMagicNumber((ushort)numericValue, stringValue);
            }
            else if (numericType.Name == typeof(uint).Name)
            {
                valid = AssertMagicNumber((uint)numericValue, stringValue);
            }
            else if (numericType.Name == typeof(ulong).Name)
            {
                valid = AssertMagicNumber((ulong)numericValue, stringValue);
            }
            else
            {
                valid = true;
            }

            if (!valid)
            {
                context.ReportDiagnostic(Diagnostic.Create(Rule, context.Symbol.Locations.First()));
            }
        }

        internal static bool AssertMagicNumber(ushort magicNumber, string value)
        {
            if (value.Length < sizeof(ushort))
            {
                value = value.PadRight(sizeof(ushort), '\0');
            }

            return (magicNumber == BitConverter.ToUInt16(Encoding.UTF8.GetBytes(value), 0));
        }

        internal static bool AssertMagicNumber(uint magicNumber, string value)
        {
            if (value.Length < sizeof(uint))
            {
                value = value.PadRight(sizeof(uint), '\0');
            }

            return (magicNumber == BitConverter.ToUInt32(Encoding.UTF8.GetBytes(value), 0));
        }

        internal static bool AssertMagicNumber(ulong magicNumber, string value)
        {
            if (value.Length < sizeof(ulong))
            {
                value = value.PadRight(sizeof(ulong), '\0');
            }

            return (magicNumber == BitConverter.ToUInt64(Encoding.UTF8.GetBytes(value), 0));
        }


        private static void AnalyzeSymbolOld(SyntaxNodeAnalysisContext context)
        {
            throw new NotImplementedException();
            var attribute = (AttributeSyntax)context.Node;
            if (!(attribute.ArgumentList?.Arguments.FirstOrDefault()?.Expression is TypeOfExpressionSyntax argumentExpression))
                return;

            var semanticModel = context.SemanticModel;
            if (!Equals(semanticModel.GetTypeInfo(attribute).Type.Name, "MagicNumberAttribute"))
                return;

            //// TODO: Replace the following code with your own analysis, generating Diagnostic objects for any issues you find
            //var namedTypeSymbol = (INamedTypeSymbol)context.Symbol;

            //// Find just those named type symbols with names containing lowercase letters.
            //if (namedTypeSymbol.Name.ToCharArray().Any(char.IsLower))
            //{
            //    // For all such symbols, produce a diagnostic.
            //    var diagnostic = Diagnostic.Create(Rule, namedTypeSymbol.Locations[0], namedTypeSymbol.Name);

            //    context.ReportDiagnostic(diagnostic);
            //}
        }
    }
}
