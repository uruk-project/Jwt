using Microsoft.CodeAnalysis.Diagnostics;

namespace JsonWebToken.Analyzers.Test
{
    /// <summary>
    /// Generic superclass of all Unit Tests for DiagnosticAnalyzers
    /// </summary>
    public abstract class DiagnosticVerifier<T> : DiagnosticVerifier where T : DiagnosticAnalyzer, new()
    {
        protected override DiagnosticAnalyzer GetDiagnosticAnalyzer()
        {
            return new T();
        }
    }
}