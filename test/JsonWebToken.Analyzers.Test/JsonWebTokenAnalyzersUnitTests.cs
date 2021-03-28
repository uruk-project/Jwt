using System.Threading.Tasks;
using Xunit;

namespace JsonWebToken.Analyzers.Test
{
    public class JsonWebTokenAnalyzersUnitTest
    {
        [Fact]
        public async Task NoIssue_NoDiagnostic()
        {
            var test = @"";

            await CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.VerifyAnalyzerAsync(test);
        }

        [Fact]
        public async Task FixMagicNumberByValue()
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
        // ""dir""=7498084U
        [MagicNumber(""dir"")]
        public const uint Dir = 7498083U;

        // ""KW""=22347
        [MagicNumber(""KW"")]
        private const ushort _KW = 22346;

        // ""ECDH-ES""=23438483855262533UL
        [MagicNumber(""ECDH-ES"")]
        private const ulong _ECDH_ES = 23438483855262532u;

        // """"=0
        [MagicNumber("""")]
        public const uint Zero = 1;
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
        // ""dir""=7498084U
        [MagicNumber(""dir"")]
        public const uint Dir = 7498084U;

        // ""KW""=22347
        [MagicNumber(""KW"")]
        private const ushort _KW = 22347;

        // ""ECDH-ES""=23438483855262533UL
        [MagicNumber(""ECDH-ES"")]
        private const ulong _ECDH_ES = 23438483855262533UL;

        // """"=0
        [MagicNumber("""")]
        public const uint Zero = 0;
    }
}";

            var expected1 = CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.Diagnostic(MagicNumberAnalyzer.DiagnosticId)
                .WithArguments("7498083", "dir", "cir", "7498084")
                .WithLocation(20, 27);
            var expected2 = CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.Diagnostic(MagicNumberAnalyzer.DiagnosticId)
                .WithArguments("22346", "KW", "JW", "22347")
                .WithLocation(24, 30);
            var expected3 = CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.Diagnostic(MagicNumberAnalyzer.DiagnosticId)
                .WithArguments("23438483855262532", "ECDH-ES", "DCDH-ES", "23438483855262533")
                .WithLocation(28, 29);
            var expected4 = CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.Diagnostic(MagicNumberAnalyzer.DiagnosticId)
            .WithArguments("1", "", "", "0")
            .WithLocation(32, 27); await CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.VerifyCodeFixAsync(test, new[] { expected1, expected2, expected3, expected4 }, fixtest, "FixMagicValue");
        }

        [Fact]
        public async Task FixMagicNumberByAttribute()
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
        // ""dir""=7498084U
        [MagicNumber(""kir"")]
        public const uint Dir = 7498084U;

        // ""KW""=22347
        [MagicNumber(""KB"")]
        private const ushort _KW = 22347;

        // ""ECDH-ES""=23438483855262533UL
        [MagicNumber(""ECDH-Ez"")]
        private const ulong _ECDH_ES = 23438483855262533U;

        // ""zero""=0
        [MagicNumber(""zero"")]
        public const uint Zero = 0;
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
        // ""dir""=7498084U
        [MagicNumber(""dir"")]
        public const uint Dir = 7498084U;

        // ""KW""=22347
        [MagicNumber(""KW"")]
        private const ushort _KW = 22347;

        // ""ECDH-ES""=23438483855262533UL
        [MagicNumber(""ECDH-ES"")]
        private const ulong _ECDH_ES = 23438483855262533U;

        // ""zero""=0
        [MagicNumber("""")]
        public const uint Zero = 0;
    }
}";

            var expected1 = CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.Diagnostic(MagicNumberAnalyzer.DiagnosticId)
                .WithArguments("7498084", "kir", "dir", "7498091")
                .WithLocation(20, 27);
             var expected2 = CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.Diagnostic(MagicNumberAnalyzer.DiagnosticId)
                .WithArguments("22347", "KB", "KW", "16971")
                .WithLocation(24, 30);
            var expected3 = CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.Diagnostic(MagicNumberAnalyzer.DiagnosticId)
                .WithArguments("23438483855262533", "ECDH-Ez", "ECDH-ES", "34416007946978117")
                .WithLocation(28, 29);
            var expected4 = CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.Diagnostic(MagicNumberAnalyzer.DiagnosticId)
                .WithArguments("0", "zero", "", "1869768058")
                .WithLocation(32, 27);
            await CSharpCodeFixVerifier<MagicNumberAnalyzer, MagicNumberCodeFixProvider>.VerifyCodeFixAsync(test, new [] { expected1, expected2, expected3, expected4 }, fixtest, "FixMagicAttribute");
        }
    }
}
