using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Formatting;
using Microsoft.CodeAnalysis.Simplification;
using Microsoft.CodeAnalysis.Testing;
using Microsoft.CodeAnalysis.Text;
using Newtonsoft.Json;
using Xunit;

namespace JsonWebToken.Analyzers.Test
{
    /// <summary>
    /// Superclass of all Unit Tests for DiagnosticAnalyzers
    /// </summary>
    public abstract partial class DiagnosticVerifier
    {
        /// <summary>
        /// Get the analyzer being tested - to be implemented in non-abstract class
        /// </summary>
        protected abstract DiagnosticAnalyzer GetDiagnosticAnalyzer();

        protected async Task VerifyBasicHasNoDiagnosticsAsync(string source, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB = Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14) =>
            await VerifyBasicDiagnosticAsync(source, new DiagnosticResult[] { }, languageVersionVB).ConfigureAwait(true);

        protected async Task VerifyBasicHasNoDiagnosticsAsync(string source1, string source2, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB = Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14) =>
            await VerifyBasicDiagnosticAsync(new[] { source1, source2 }, new DiagnosticResult[] { }, languageVersionVB).ConfigureAwait(true);

        protected async Task VerifyBasicHasNoDiagnosticsAsync(string[] sources, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB = Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14) =>
            await VerifyBasicDiagnosticAsync(sources, new DiagnosticResult[] { }, languageVersionVB).ConfigureAwait(true);

        protected async Task VerifyCSharpHasNoDiagnosticsAsync(string source, LanguageVersion languageVersion = LanguageVersion.CSharp6) =>
            await VerifyCSharpDiagnosticAsync(source, new DiagnosticResult[] { }, languageVersion).ConfigureAwait(true);

        protected async Task VerifyCSharpHasNoDiagnosticsAsync(string source1, string source2, LanguageVersion languageVersion = LanguageVersion.CSharp6) =>
            await VerifyCSharpDiagnosticAsync(new[] { source1, source2 }, new DiagnosticResult[] { }, languageVersion).ConfigureAwait(true);

        protected async Task VerifyCSharpHasNoDiagnosticsAsync(string[] sources, LanguageVersion languageVersion = LanguageVersion.CSharp6) =>
            await VerifyCSharpDiagnosticAsync(sources, new DiagnosticResult[] { }, languageVersion).ConfigureAwait(true);

        /// <summary>
        /// Called to test a C# DiagnosticAnalyzer when applied on the single inputted string as a source
        /// Note: input a DiagnosticResult for each Diagnostic expected
        /// </summary>
        /// <param name="source">A class in the form of a string to run the analyzer on</param>
        /// <param name="expected"> DiagnosticResults that should appear after the analyzer is run on the source</param>
        /// <param name="languageVersion">The C# language version, defaults to the latest stable version.</param>
        protected async Task VerifyCSharpDiagnosticAsync(string source, DiagnosticResult[] expected, LanguageVersion languageVersion = LanguageVersion.CSharp6) =>
            await VerifyDiagnosticsAsync(new[] { source }, LanguageNames.CSharp, GetDiagnosticAnalyzer(), expected, languageVersion, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14).ConfigureAwait(true);

        protected async Task VerifyCSharpDiagnosticAsync(string source, DiagnosticResult expected, LanguageVersion languageVersion = LanguageVersion.CSharp6) =>
            await VerifyDiagnosticsAsync(new[] { source }, LanguageNames.CSharp, GetDiagnosticAnalyzer(), new[] { expected }, languageVersion, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14).ConfigureAwait(true);

        protected async Task VerifyCSharpDiagnosticAsync(string source, DiagnosticResult expected1, DiagnosticResult expected2, LanguageVersion languageVersion = LanguageVersion.CSharp6) =>
            await VerifyDiagnosticsAsync(new[] { source }, LanguageNames.CSharp, GetDiagnosticAnalyzer(), new[] { expected1, expected2 }, languageVersion, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14).ConfigureAwait(true);

        /// <summary>
        /// Called to test a VB DiagnosticAnalyzer when applied on the single inputted string as a source
        /// Note: input a DiagnosticResult for each Diagnostic expected
        /// </summary>
        /// <param name="source">A class in the form of a string to run the analyzer on</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the source</param>
        /// <param name="languageVersion">The VB language version, defaults to the latest stable version.</param>
        protected async Task VerifyBasicDiagnosticAsync(string source, DiagnosticResult[] expected, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersion = Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14) =>
            await VerifyDiagnosticsAsync(new[] { source }, LanguageNames.VisualBasic, GetDiagnosticAnalyzer(), expected, LanguageVersion.CSharp6, languageVersion).ConfigureAwait(true);

        protected async Task VerifyBasicDiagnosticAsync(string source, DiagnosticResult expected, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB = Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14) =>
            await VerifyDiagnosticsAsync(new[] { source }, LanguageNames.VisualBasic, GetDiagnosticAnalyzer(), new[] { expected }, LanguageVersion.CSharp6, languageVersionVB).ConfigureAwait(true);

        protected async Task VerifyBasicDiagnosticAsync(string source, DiagnosticResult expected1, DiagnosticResult expected2, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB = Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14) =>
            await VerifyDiagnosticsAsync(new[] { source }, LanguageNames.VisualBasic, GetDiagnosticAnalyzer(), new[] { expected1, expected2 }, LanguageVersion.CSharp6, languageVersionVB).ConfigureAwait(true);

        /// <summary>
        /// Called to test a C# DiagnosticAnalyzer when applied on the inputted strings as a source
        /// Note: input a DiagnosticResult for each Diagnostic expected
        /// </summary>
        /// <param name="sources">An array of strings to create source documents from to run the analyzers on</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the sources</param>
        /// <param name="languageVersion">The C# language version, defaults to the latest stable version.</param>
        protected async Task VerifyCSharpDiagnosticAsync(string[] sources, DiagnosticResult[] expected, LanguageVersion languageVersion = LanguageVersion.CSharp6) =>
            await VerifyDiagnosticsAsync(sources, LanguageNames.CSharp, GetDiagnosticAnalyzer(), expected, languageVersion, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14).ConfigureAwait(true);

        /// <summary>
        /// Called to test a VB DiagnosticAnalyzer when applied on the inputted strings as a source
        /// Note: input a DiagnosticResult for each Diagnostic expected
        /// </summary>
        /// <param name="sources">An array of strings to create source documents from to run the analyzers on</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the sources</param>
        /// <param name="languageVersion">The VB language version, defaults to the latest stable version.</param>
        protected async Task VerifyBasicDiagnosticAsync(string[] sources, DiagnosticResult[] expected, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersion = Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14) =>
            await VerifyDiagnosticsAsync(sources, LanguageNames.VisualBasic, GetDiagnosticAnalyzer(), expected, LanguageVersion.CSharp6, languageVersion).ConfigureAwait(true);

        /// <summary>
        /// General method that gets a collection of actual diagnostics found in the source after the analyzer is run,
        /// then verifies each of them.
        /// </summary>
        /// <param name="sources">An array of strings to create source documents from to run teh analyzers on</param>
        /// <param name="language">The language of the classes represented by the source strings</param>
        /// <param name="analyzer">The analyzer to be run on the source code</param>
        /// <param name="expected">DiagnosticResults that should appear after the analyzer is run on the sources</param>
        /// <param name="languageVersionCSharp">The C# language version, default to latest.</param>
        /// <param name="languageVersionVB">The VB language version, default to latest.</param>
        private async static Task VerifyDiagnosticsAsync(string[] sources, string language, DiagnosticAnalyzer analyzer, DiagnosticResult[] expected, LanguageVersion languageVersionCSharp, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB)
        {
            var diagnostics = await GetSortedDiagnosticsAsync(sources, language, analyzer, languageVersionCSharp, languageVersionVB).ConfigureAwait(true);
            var defaultFilePath = language == LanguageNames.CSharp ? CSharpDefaultFilePath : VisualBasicDefaultFilePath;
            VerifyDiagnosticResults(diagnostics, analyzer, defaultFilePath, expected);
        }


        /// <summary>
        /// Checks each of the actual Diagnostics found and compares them with the corresponding DiagnosticResult in the array of expected results.
        /// Diagnostics are considered equal only if the DiagnosticResultLocation, Id, Severity, and Message of the DiagnosticResult match the actual diagnostic.
        /// </summary>
        /// <param name="actualResults">The Diagnostics found by the compiler after running the analyzer on the source code</param>
        /// <param name="analyzer">The analyzer that was being run on the sources</param>
        /// <param name="expectedResults">Diagnsotic Results that should have appeared in the code</param>
        private static void VerifyDiagnosticResults(IEnumerable<Diagnostic> actualResults, DiagnosticAnalyzer analyzer, string defaultFilePath, params DiagnosticResult[] expectedResults)
        {
            var expectedCount = expectedResults.Length;
            var actualCount = actualResults.Count();

            if (expectedCount != actualCount)
            {
                var diagnosticsOutput = actualResults.Any() ? FormatDiagnostics(analyzer, actualResults.ToArray()) : "    NONE.";

                Assert.True(false, $"Mismatch between number of diagnostics returned, expected \"{expectedCount}\" actual \"{actualCount}\"\r\n\r\nDiagnostics:\r\n{diagnosticsOutput}\r\n");
            }

            for (int i = 0; i < expectedResults.Length; i++)
            {
                var actual = actualResults.ElementAt(i);
                var expected = expectedResults[i].WithDefaultPath(defaultFilePath);

                if (!expected.HasLocation)
                {
                    if (actual.Location != Location.None)
                    {
                        Assert.True(false, $"Expected:\nA project diagnostic with No location\nActual:\n{FormatDiagnostics(analyzer, actual)}");
                    }
                }
                else
                {
                    VerifyDiagnosticLocation(analyzer, actual, actual.Location, expected.Spans.First());
                    var additionalLocations = actual.AdditionalLocations.ToArray();

                    if (additionalLocations.Length != expected.Spans.Length - 1)
                    {
                        Assert.True(false, $"Expected {expected.Spans.Length - 1} additional locations but got {additionalLocations.Length} for Diagnostic:\r\n    {FormatDiagnostics(analyzer, actual)}\r\n");
                    }

                    for (int j = 0; j < additionalLocations.Length; ++j)
                    {
                        VerifyDiagnosticLocation(analyzer, actual, additionalLocations[j], expected.Spans[j + 1]);
                    }
                }

                if (actual.Id != expected.Id)
                    Assert.True(false, $"Expected diagnostic id to be \"{expected.Id}\" was \"{actual.Id}\"\r\n\r\nDiagnostic:\r\n    {FormatDiagnostics(analyzer, actual)}\r\n");

                if (actual.Severity != expected.Severity)
                    Assert.True(false, $"Expected diagnostic severity to be \"{expected.Severity}\" was \"{actual.Severity}\"\r\n\r\nDiagnostic:\r\n    {FormatDiagnostics(analyzer, actual)}\r\n");

                if (actual.GetMessage() != expected.Message)
                    Assert.True(false, $"Expected diagnostic message to be \"{expected.Message}\" was \"{actual.GetMessage()}\"\r\n\r\nDiagnostic:\r\n    {FormatDiagnostics(analyzer, actual)}\r\n");
            }
        }

        /// <summary>
        /// Helper method to VerifyDiagnosticResult that checks the location of a diagnostic and compares it with the location in the expected DiagnosticResult.
        /// </summary>
        /// <param name="analyzer">The analyzer that was being run on the sources</param>
        /// <param name="diagnostic">The diagnostic that was found in the code</param>
        /// <param name="actual">The Location of the Diagnostic found in the code</param>
        /// <param name="expected">The DiagnosticResultLocation that should have been found</param>
        private static void VerifyDiagnosticLocation(DiagnosticAnalyzer analyzer, Diagnostic diagnostic, Location actual, DiagnosticLocation expected)
        {
            var actualSpan = actual.GetLineSpan();

            Assert.True(actualSpan.Path == expected.Span.Path || (actualSpan.Path != null && actualSpan.Path.Contains("Test0.") && expected.Span.Path.Contains("Test.")),
                $"Expected diagnostic to be in file \"{expected.Span.Path}\" was actually in file \"{actualSpan.Path}\"\r\n\r\nDiagnostic:\r\n    {FormatDiagnostics(analyzer, diagnostic)}\r\n");

            var actualLinePosition = actualSpan.StartLinePosition;

            // Only check line position if there is an actual line in the real diagnostic
            if (actualLinePosition.Line > 0)
                if (actualLinePosition.Line != expected.Span.StartLinePosition.Line)
                    Assert.True(false, $"Expected diagnostic to be on line \"{expected.Span.StartLinePosition.Line + 1}\" was actually on line \"{actualLinePosition.Line + 1}\"\r\n\r\nDiagnostic:\r\n    {FormatDiagnostics(analyzer, diagnostic)}\r\n");

            // Only check column position if there is an actual column position in the real diagnostic
            if (actualLinePosition.Character > 0)
                if (actualLinePosition.Character != expected.Span.StartLinePosition.Character)
                    Assert.True(false, $"Expected diagnostic to start at column \"{expected.Span.StartLinePosition.Character + 1}\" was actually at column \"{actualLinePosition.Character + 1}\"\r\n\r\nDiagnostic:\r\n    {FormatDiagnostics(analyzer, diagnostic)}\r\n");
        }

        /// <summary>
        /// Helper method to format a Diagnostic into an easily reasible string
        /// </summary>
        /// <param name="analyzer">The analyzer that this Verifer tests</param>
        /// <param name="diagnostics">The Diagnostics to be formatted</param>
        /// <returns>The Diagnostics formatted as a string</returns>
        private static string FormatDiagnostics(DiagnosticAnalyzer analyzer, params Diagnostic[] diagnostics)
        {
            var builder = new StringBuilder();
            for (int i = 0; i < diagnostics.Length; ++i)
            {
                builder.AppendLine("// " + diagnostics[i].ToString());

                var analyzerType = analyzer.GetType();
                var rules = analyzer.SupportedDiagnostics;

                foreach (var rule in rules)
                {
                    if (rule != null && rule.Id == diagnostics[i].Id)
                    {
                        var location = diagnostics[i].Location;
                        if (location == Location.None)
                        {
                            builder.AppendFormat("GetGlobalResult({0}.{1})", analyzerType.Name, rule.Id);
                        }
                        else
                        {
                            Assert.True(location.IsInSource, $"Test base does not currently handle diagnostics in metadata locations. Diagnostic in metadata:\r\n{diagnostics[i]}");

                            var resultMethodName = diagnostics[i].Location.SourceTree.FilePath.EndsWith(".cs") ? "GetCSharpResultAt" : "GetBasicResultAt";
                            var linePosition = diagnostics[i].Location.GetLineSpan().StartLinePosition;

                            builder.AppendFormat("{0}({1}, {2}, {3}.{4})",
                                resultMethodName,
                                linePosition.Line + 1,
                                linePosition.Character + 1,
                                analyzerType.Name,
                                rule.Id);
                        }

                        if (i != diagnostics.Length - 1) builder.Append(',');

                        builder.AppendLine();
                        break;
                    }
                }
            }
            return builder.ToString();
        }


        private static readonly MetadataReference CorlibReference = MetadataReference.CreateFromFile(typeof(object).Assembly.Location);
        private static readonly MetadataReference SystemCoreReference = MetadataReference.CreateFromFile(typeof(Enumerable).Assembly.Location);
        private static readonly MetadataReference RegexReference = MetadataReference.CreateFromFile(typeof(System.Text.RegularExpressions.Regex).Assembly.Location);
        private static readonly MetadataReference CSharpSymbolsReference = MetadataReference.CreateFromFile(typeof(CSharpCompilation).Assembly.Location);
        private static readonly MetadataReference CodeAnalysisReference = MetadataReference.CreateFromFile(typeof(Compilation).Assembly.Location);
        private static readonly MetadataReference JsonNetReference = MetadataReference.CreateFromFile(typeof(JsonConvert).Assembly.Location);

        internal static readonly string DefaultFilePathPrefix = nameof(Test);
        internal static readonly string CSharpDefaultFileExt = "cs";
        internal static readonly string VisualBasicDefaultExt = "vb";
        internal static readonly string CSharpDefaultFilePath = DefaultFilePathPrefix + 0 + "." + CSharpDefaultFileExt;
        internal static readonly string VisualBasicDefaultFilePath = DefaultFilePathPrefix + 0 + "." + VisualBasicDefaultExt;
        internal static readonly string TestProjectName = "TestProject";

        /// <summary>
        /// Given classes in the form of strings, their language, and an IDiagnosticAnlayzer to apply to it, return the diagnostics found in the string after converting it to a document.
        /// </summary>
        /// <param name="sources">Classes in the form of strings</param>
        /// <param name="language">The language the soruce classes are in</param>
        /// <param name="analyzer">The analyzer to be run on the sources</param>
        /// <param name="languageVersionCSharp">C# language version used for compiling the test project, required unless you inform the VB language version.</param>
        /// <param name="languageVersionVB">VB language version used for compiling the test project, required unless you inform the C# language version.</param>
        /// <returns>An IEnumerable of Diagnostics that surfaced in teh source code, sorted by Location</returns>
        private static async Task<Diagnostic[]> GetSortedDiagnosticsAsync(string[] sources, string language, DiagnosticAnalyzer analyzer, LanguageVersion languageVersionCSharp, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB) =>
            await GetSortedDiagnosticsFromDocumentsAsync(analyzer, GetDocuments(sources, language, languageVersionCSharp, languageVersionVB)).ConfigureAwait(true);

        /// <summary>
        /// Given an analyzer and a document to apply it to, run the analyzer and gather an array of diagnostics found in it.
        /// The returned diagnostics are then ordered by location in the source document.
        /// </summary>
        /// <param name="analyzer">The analyzer to run on the documents</param>
        /// <param name="documents">The Documents that the analyzer will be run on</param>
        /// <returns>An IEnumerable of Diagnostics that surfaced in teh source code, sorted by Location</returns>
        protected async static Task<Diagnostic[]> GetSortedDiagnosticsFromDocumentsAsync(DiagnosticAnalyzer analyzer, Document[] documents)
        {
            var projects = new HashSet<Project>();
            foreach (var document in documents)
                projects.Add(document.Project);

            var diagnostics = new List<Diagnostic>();
            foreach (var project in projects)
            {
                var compilation = await project.GetCompilationAsync().ConfigureAwait(true);
                var compilationWithAnalyzers = compilation.WithAnalyzers(ImmutableArray.Create(analyzer));
                var diags = await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync().ConfigureAwait(true);
                CheckIfAnalyzerThrew(await compilationWithAnalyzers.GetAllDiagnosticsAsync().ConfigureAwait(true));
                foreach (var diag in diags)
                {
                    if (diag.Location == Location.None || diag.Location.IsInMetadata)
                    {
                        diagnostics.Add(diag);
                    }
                    else
                    {
                        foreach (var document in project.Documents)
                        {
                            var tree = await document.GetSyntaxTreeAsync().ConfigureAwait(true);
                            if (tree == diag.Location.SourceTree) diagnostics.Add(diag);
                        }
                    }
                }
            }
            var results = SortDiagnostics(diagnostics);
            return results;
        }

        /// <param name="diags">The compiler diagnostics at a given compilation.</param>
        /// <remarks>
        /// Todo: Remove/Update when https://github.com/dotnet/roslyn/issues/2580 is completed and there is
        /// an api to check for analyzer exceptions
        /// </remarks>
        private static void CheckIfAnalyzerThrew(ImmutableArray<Diagnostic> diags)
        {
            var exceptionAnalyzer = diags.FirstOrDefault(d => d.Id == "AD0001");
            if (exceptionAnalyzer != null) throw new Exception($"Analyzer threw. Details:\nMessage:{exceptionAnalyzer.GetMessage()}.");
        }

        private static Diagnostic[] SortDiagnostics(List<Diagnostic> diagnostics) =>
            diagnostics.OrderBy(d => d.Location.SourceTree.FilePath).ThenBy(d => d.Location.SourceSpan.Start).ToArray();

        #region Set up compilation and documents
        /// <summary>
        /// Given an array of strings as sources and a language, turn them into a project and return the documents and spans of it.
        /// </summary>
        /// <param name="sources">Classes in the form of strings</param>
        /// <param name="language">The language the source code is in</param>
        /// <param name="languageVersionCSharp">C# language version used for compiling the test project, required unless you inform the VB language version.</param>
        /// <param name="languageVersionVB">VB language version used for compiling the test project, required unless you inform the C# language version.</param>
        /// <returns>A Tuple containing the Documents produced from the sources and thier TextSpans if relevant</returns>
        public static Document[] GetDocuments(string[] sources, string language, LanguageVersion languageVersionCSharp, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB)
        {
            if (language != LanguageNames.CSharp && language != LanguageNames.VisualBasic)
                throw new ArgumentException("Unsupported Language");

            for (int i = 0; i < sources.Length; i++)
            {
                var fileName = language == LanguageNames.CSharp ? nameof(Test) + i + ".cs" : nameof(Test) + i + ".vb";
            }

            var project = CreateProject(sources, language, languageVersionCSharp, languageVersionVB);
            var documents = project.Documents.ToArray();

            if (sources.Length != documents.Length)
            {
                throw new SystemException("Amount of sources did not match amount of Documents created");
            }

            return documents;
        }

        /// <summary>
        /// Create a Document from a string through creating a project that contains it.
        /// </summary>
        /// <param name="source">Classes in the form of a string</param>
        /// <param name="language">The language the source code is in</param>
        /// <param name="languageVersionCSharp">C# language version used for compiling the test project, required unless you inform the VB language version.</param>
        /// <param name="languageVersionVB">VB language version used for compiling the test project, required unless you inform the C# language version.</param>
        /// <returns>A Document created from the source string</returns>
        public static Document CreateDocument(string source,
            string language,
            LanguageVersion languageVersionCSharp,
            Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB) =>
            CreateProject(new[] { source }, language, languageVersionCSharp, languageVersionVB).Documents.First();

        /// <summary>
        /// Create a project using the inputted strings as sources.
        /// </summary>
        /// <param name="sources">Classes in the form of strings</param>
        /// <param name="language">The language the source code is in</param>
        /// <param name="languageVersionCSharp">C# language version used for compiling the test project, required unless you inform the VB language version.</param>
        /// <param name="languageVersionVB">VB language version used for compiling the test project, required unless you inform the C# language version.</param>
        /// <returns>A Project created out of the Douments created from the source strings</returns>
        public static Project CreateProject(string[] sources,
            string language,
            LanguageVersion languageVersionCSharp,
            Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB)
        {
            var fileNamePrefix = DefaultFilePathPrefix;
            string fileExt;
            ParseOptions parseOptions;
            if (language == LanguageNames.CSharp)
            {
                fileExt = CSharpDefaultFileExt;
                parseOptions = new CSharpParseOptions(languageVersionCSharp);
            }
            else
            {
                fileExt = VisualBasicDefaultExt;
                parseOptions = new Microsoft.CodeAnalysis.VisualBasic.VisualBasicParseOptions(languageVersionVB);
            }

            var projectId = ProjectId.CreateNewId(debugName: TestProjectName);
#pragma warning disable CC0022
            var workspace = new AdhocWorkspace();
#pragma warning restore CC0022

            var projectInfo = ProjectInfo.Create(projectId, VersionStamp.Create(), TestProjectName,
                TestProjectName, language,
                parseOptions: parseOptions,
                metadataReferences: ImmutableList.Create(
                    CorlibReference, SystemCoreReference, RegexReference,
                    CSharpSymbolsReference, CodeAnalysisReference, JsonNetReference));

            workspace.AddProject(projectInfo);

            var count = 0;
            foreach (var source in sources)
            {
                var newFileName = fileNamePrefix + count + "." + fileExt;
                workspace.AddDocument(projectId, newFileName, SourceText.From(source));
                count++;
            }

            var project = workspace.CurrentSolution.GetProject(projectId);
            var newCompilationOptions = project!.CompilationOptions!.WithSpecificDiagnosticOptions(diagOptions);
            var newSolution = workspace.CurrentSolution.WithProjectCompilationOptions(projectId, newCompilationOptions);
            var newProject = newSolution.GetProject(projectId);
            return newProject!;
        }

        private static readonly Dictionary<string, ReportDiagnostic> diagOptions = Enumerable.Range(1, 1000).Select(i => $"CC{i:D4}").ToDictionary(id => id, id => ReportDiagnostic.Default);

        #endregion

        /// <summary>
        /// Given a document, turn it into a string based on the syntax root
        /// </summary>
        /// <param name="document">The Document to be converted to a string</param>
        /// <returns>A string contianing the syntax of the Document after formatting</returns>
        public static async Task<string> GetStringFromDocumentAsync(Document document)
        {
            var simplifiedDoc = await Simplifier.ReduceAsync(document, Simplifier.Annotation).ConfigureAwait(true);
            var root = await simplifiedDoc.GetSyntaxRootAsync().ConfigureAwait(true);
            root = Formatter.Format(root, Formatter.Annotation, simplifiedDoc.Project.Solution.Workspace);
            return root.GetText().ToString();
        }

        public static async Task<string> FormatSourceAsync(string language, string source, LanguageVersion languageVersionCSharp = LanguageVersion.CSharp6, Microsoft.CodeAnalysis.VisualBasic.LanguageVersion languageVersionVB = Microsoft.CodeAnalysis.VisualBasic.LanguageVersion.VisualBasic14)
        {
            var document = CreateDocument(source, language, languageVersionCSharp, languageVersionVB);
            var newDoc = await Formatter.FormatAsync(document).ConfigureAwait(true);
            return (await newDoc.GetSyntaxRootAsync().ConfigureAwait(true)).ToFullString();
        }
    }
}