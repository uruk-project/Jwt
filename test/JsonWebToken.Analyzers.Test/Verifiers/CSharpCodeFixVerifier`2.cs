using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;
using Microsoft.CodeAnalysis.Testing.Verifiers;

namespace JsonWebToken.Analyzers.Test
{
    public static partial class CSharpCodeFixVerifier<TAnalyzer, TCodeFix>
    where TAnalyzer : DiagnosticAnalyzer, new()
    where TCodeFix : CodeFixProvider, new()
    {
        public static DiagnosticResult Diagnostic()
            => CSharpCodeFixVerifier<TAnalyzer, TCodeFix, XUnitVerifier>.Diagnostic();

        public static DiagnosticResult Diagnostic(string diagnosticId)
            => CSharpCodeFixVerifier<TAnalyzer, TCodeFix, XUnitVerifier>.Diagnostic(diagnosticId);

        public static DiagnosticResult Diagnostic(DiagnosticDescriptor descriptor)
            => new DiagnosticResult(descriptor);

        public static Task VerifyAnalyzerAsync(string source, params DiagnosticResult[] expected)
        {
            var test = new Test { TestCode = source };
            test.ExpectedDiagnostics.AddRange(expected);
            return test.RunAsync();
        }

        public static Task VerifyCodeFixAsync(string source, string fixedSource, string? codeActionEquivalenceKey = null)
            => VerifyCodeFixAsync(source, DiagnosticResult.EmptyDiagnosticResults, fixedSource, codeActionEquivalenceKey);

        public static Task VerifyCodeFixAsync(string source, DiagnosticResult expected, string fixedSource, string? codeActionEquivalenceKey = null)
            => VerifyCodeFixAsync(source, new[] { expected }, fixedSource, codeActionEquivalenceKey);

        public static Task VerifyCodeFixAsync(string source, DiagnosticResult[] expected, string fixedSource, string? codeActionEquivalenceKey = null)
        {
            var test = new Test
            {
                TestCode = source,
                FixedCode = fixedSource,
                CodeActionEquivalenceKey = codeActionEquivalenceKey
            };

            test.ExpectedDiagnostics.AddRange(expected);
            return test.RunAsync();
        }

        public class Test : CodeFixTest<XUnitVerifier>
        {
            public override string Language => LanguageNames.CSharp;

            protected override string DefaultFileExt => "cs";

            public override Type SyntaxKindType => typeof(SyntaxKind);

            protected override CompilationOptions CreateCompilationOptions()
                => new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true);

            protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
            {
                yield return new TAnalyzer();
            }

            protected override IEnumerable<CodeFixProvider> GetCodeFixProviders()
            {
                yield return new TCodeFix();
            }

            protected override ParseOptions CreateParseOptions()
            {
                return new CSharpParseOptions(LanguageVersion.Default);
            }
        }
    }
}