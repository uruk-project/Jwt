using System;
using System.Collections.Immutable;
using System.Composition;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace JsonWebToken.Analyzers
{
    [ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(MagicNumberCodeFixProvider)), Shared]
    public class MagicNumberCodeFixProvider : CodeFixProvider
    {
        public sealed override ImmutableArray<string> FixableDiagnosticIds
        {
            get { return ImmutableArray.Create(MagicNumberAnalyzer.DiagnosticId); }
        }

        public sealed override FixAllProvider GetFixAllProvider()
        {
            return WellKnownFixAllProviders.BatchFixer;
        }

        public sealed override async Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);

            var nodeToFix = root.FindNode(context.Span);
            if (nodeToFix == null)
            {
                return;
            }

            foreach (var diagnostic in context.Diagnostics)
            {
                var diagnosticSpan = diagnostic.Location.SourceSpan;

                context.RegisterCodeFix(CodeAction.Create("Fix magic value", c => ChangeValue(context.Document, diagnostic, c), "FixMagicValue"), diagnostic);
                context.RegisterCodeFix(CodeAction.Create("Fix magic attribute", c => ChangeAttribute(context.Document, diagnostic, c), "FixMagicAttribute" ), diagnostic);
            }
        }

        private async static Task<Document> ChangeValue(Document document, Diagnostic diagnostic, CancellationToken cancellationToken)
        {
            if (diagnostic.Properties.TryGetValue("stringValue", out var value))
            {
                var equalClause = SyntaxFactory.EqualsValueClause(SyntaxFactory.LiteralExpression(SyntaxKind.NumericLiteralExpression, CreateMagicValue(value)));
                var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
                var variable = root.FindNode(diagnostic.Location.SourceSpan) as VariableDeclaratorSyntax;
                var newVariable = variable.WithInitializer(equalClause);
                var newRoot = root.ReplaceNode(variable, newVariable);
                document = document.WithSyntaxRoot(newRoot);
            }

            return document;
        }

        internal static SyntaxToken CreateMagicValue(string value)
        {
            SyntaxToken token;
            if (value.Length <= sizeof(ushort))
            {
                value = value.PadRight(sizeof(ushort), '\0');
                token = SyntaxFactory.Literal(BitConverter.ToUInt16(Encoding.UTF8.GetBytes(value), 0));
            }
            else if (value.Length <= sizeof(uint))
            {
                value = value.PadRight(sizeof(uint), '\0');
                token = SyntaxFactory.Literal(BitConverter.ToUInt32(Encoding.UTF8.GetBytes(value), 0));
            }
            else if (value.Length <= sizeof(ulong))
            {
                value = value.PadRight(sizeof(ulong), '\0');
                token = SyntaxFactory.Literal(BitConverter.ToUInt64(Encoding.UTF8.GetBytes(value), 0));
            }
            else
            {
                token = default;
            }

            return token;
        }



        private async static Task<Document> ChangeAttribute(Document document, Diagnostic diagnostic, CancellationToken cancellationToken)
        {
            if (diagnostic.Properties.TryGetValue("numericValue", out var value) &&
                diagnostic.Properties.TryGetValue("type", out var type))
            {
                var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
                var variable = root.FindNode(diagnostic.Location.SourceSpan) as VariableDeclaratorSyntax;

                var attributeArgument = SyntaxFactory.AttributeArgument(
                    null, null, SyntaxFactory.LiteralExpression(SyntaxKind.StringLiteralExpression, CreateMagicStringValue(value, type)));

                var attribute = ((FieldDeclarationSyntax)variable.Parent.Parent).AttributeLists.First();

                var newAttribute = SyntaxFactory.AttributeList(SyntaxFactory.SingletonSeparatedList(
                        SyntaxFactory.Attribute(SyntaxFactory.IdentifierName("MagicNumber"))
                        .WithArgumentList(SyntaxFactory.AttributeArgumentList(SyntaxFactory.SingletonSeparatedList(attributeArgument))))
                    )
                    .WithTriviaFrom(attribute);

                var newRoot = root.ReplaceNode(attribute, newAttribute);
                document = document.WithSyntaxRoot(newRoot);
            }

            return document;
        }


        internal static SyntaxToken CreateMagicStringValue(string value, string type)
        {
            byte[] byteArray;
            switch (type)
            {
                case "UInt16":
                    byteArray = BitConverter.GetBytes(ushort.Parse(value));
                    break;
                case "UInt32":
                    byteArray = BitConverter.GetBytes(uint.Parse(value));
                    break;
                case "UInt64":
                    byteArray = BitConverter.GetBytes(ulong.Parse(value));
                    break;
                default:
                    throw new InvalidOperationException($"{type} is not a supported type.");
            }

            return SyntaxFactory.Literal(Encoding.UTF8.GetString(byteArray.Trim()));
        }
    }
}
