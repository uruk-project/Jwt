using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VerifyCS = JsonWebToken.Analyzers.Test.CSharpCodeFixVerifier<
    JsonWebToken.Analyzers.MagicNumberAnalyzer,
    JsonWebToken.Analyzers.JsonWebTokenAnalyzersCodeFixProvider>;

namespace JsonWebToken.Analyzers.Test
{
    [TestClass]
    public class JsonWebTokenAnalyzersUnitTest
    {
        //No diagnostics expected to show up
        [TestMethod]
        public async Task TestMethod1()
        {
            var test = @"";

            await VerifyCS.VerifyAnalyzerAsync(test);
        }

        //Diagnostic and CodeFix both triggered and checked for
        [TestMethod]
        public async Task TestMethod2()
        {
            var test = @"
using System;

namespace ConsoleApplication1
{
    public class MagicNumberAttribute : Attribute
    {   
        public MagicNumberAttribute(string value)
        {
            Value = value;
        }

        public string Value { get; }
    }

    class MyClass
    {   
        [MagicNumberAttribute(""dir"")]
        public const uint Dir = 7498083u;
    }
}";

            var fixtest = @"
using System;

namespace ConsoleApplication1
{
    public class MagicNumberAttribute : Attribute
    {   
        public MagicNumberAttribute(string value)
        {
            Value = value;
        }

        public string Value { get; }
    }

    class MyClass
    {   
        [MagicNumberAttribute(""dir"")]
        public const uint Dir = 7498084u;
    }
}";

            var expected = VerifyCS.Diagnostic(MagicNumberAnalyzer.DiagnosticId).WithLocation(19, 27);
            await VerifyCS.VerifyCodeFixAsync(test, expected, fixtest);
        }
    }
}
