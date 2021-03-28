using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;

namespace JsonWebToken.Analyzers.Test
{
    public abstract class CodeFixVerifier<T, U> : CodeFixVerifier
        where T : DiagnosticAnalyzer, new()
        where U : CodeFixProvider, new()
    {
        protected override DiagnosticAnalyzer GetDiagnosticAnalyzer() => new T();

        protected override CodeFixProvider GetCodeFixProvider() => new U();
    }
}