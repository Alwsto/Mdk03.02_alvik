using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

if (args.Length < 3)
{
    Console.Error.WriteLine("Usage: MetricsRunner <source-root> <output.json> <target.cs-or-txt> [...]");
    return 2;
}
var sourceRoot = Path.GetFullPath(args[0]);
var output = Path.GetFullPath(args[1]);
var targetPaths = args.Skip(2).Select(Path.GetFullPath).ToArray();
var projectTypes = Directory.EnumerateFiles(sourceRoot, "*.cs", SearchOption.AllDirectories)
    .Where(p => !p.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar)
             && !p.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar))
    .SelectMany(p => CSharpSyntaxTree.ParseText(File.ReadAllText(p)).GetRoot()
        .DescendantNodes().OfType<BaseTypeDeclarationSyntax>().Select(t => t.Identifier.ValueText))
    .ToHashSet(StringComparer.Ordinal);
var results = new List<object>();
foreach (var path in targetPaths)
{
    var source = File.ReadAllText(path);
    var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview));
    var root = tree.GetRoot();
    var errors = tree.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToArray();
    if (errors.Length > 0) throw new InvalidDataException(path + ": " + string.Join("; ", errors.Select(e => e.ToString())));
    foreach (var type in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
    {
        var methods = type.Members.OfType<MethodDeclarationSyntax>().ToArray();
        var methodResults = methods.Select(m => AnalyzeMethod(m, tree)).ToArray();
        var dependencies = type.DescendantNodes().OfType<SimpleNameSyntax>()
            .Select(n => n.Identifier.ValueText).Where(n => projectTypes.Contains(n) && n != type.Identifier.ValueText)
            .Distinct().Order().ToArray();
        var fields = type.Members.OfType<FieldDeclarationSyntax>()
            .Where(f => !f.Modifiers.Any(SyntaxKind.StaticKeyword))
            .SelectMany(f => f.Declaration.Variables.Select(v => v.Identifier.ValueText))
            .Concat(type.ParameterList?.Parameters.Select(p => p.Identifier.ValueText) ?? [])
            .ToHashSet(StringComparer.Ordinal);
        var instanceMethods = methods.Where(m => !m.Modifiers.Any(SyntaxKind.StaticKeyword)).ToArray();
        var used = instanceMethods.Select(m => m.DescendantNodes().OfType<IdentifierNameSyntax>()
            .Select(n => n.Identifier.ValueText).Where(fields.Contains).ToHashSet()).ToArray();
        var parents = Enumerable.Range(0, instanceMethods.Length).ToArray();
        int Find(int i) { while (parents[i] != i) i = parents[i]; return i; }
        for (var i = 0; i < instanceMethods.Length; i++)
        for (var j = i + 1; j < instanceMethods.Length; j++)
        {
            bool Calls(MethodDeclarationSyntax a, MethodDeclarationSyntax b) => a.DescendantNodes()
                .OfType<InvocationExpressionSyntax>().Any(v => v.Expression.ToString() == b.Identifier.ValueText
                    || v.Expression.ToString() == "this." + b.Identifier.ValueText);
            if (used[i].Overlaps(used[j]) || Calls(instanceMethods[i], instanceMethods[j]) || Calls(instanceMethods[j], instanceMethods[i]))
                parents[Find(j)] = Find(i);
        }
        results.Add(new
        {
            File = Path.GetRelativePath(sourceRoot, path).Replace('\\', '/'),
            Sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant(),
            Class = type.Identifier.ValueText,
            Methods = methodResults,
            ControllerOrClassSummary = new
            {
                MethodCount = methods.Length,
                SumCC = methodResults.Sum(m => m.CC),
                MaxCC = methodResults.Length == 0 ? 0 : methodResults.Max(m => m.CC),
                BodyCodeLines = methodResults.Sum(m => m.LOC),
                MeanMI = methodResults.Length == 0 ? 0 : Math.Round(methodResults.Average(m => m.MI), 2),
                CBO_ProjectTypes = dependencies.Length,
                Dependencies = dependencies,
                LCOM4 = instanceMethods.Length == 0 ? 0 : Enumerable.Range(0, instanceMethods.Length).Select(Find).Distinct().Count(),
                FieldUsage = instanceMethods.Select((m, i) => new { Method = m.Identifier.ValueText, Fields = used[i].Order().ToArray() })
            }
        });
    }
}
File.WriteAllText(output, JsonSerializer.Serialize(new
{
    Tool = "GuestPass educational metrics / Roslyn syntax / 1.0",
    Method = "CC=1+if/for/foreach/while/do/catch/non-default switch labels/?:/&&/||/??/conditional access. LOC=distinct original body lines with tokens except braces. Halstead: operands=identifiers and literals; operators=remaining tokens except braces/parens/brackets/comma/semicolon. V=(N1+N2)*log2(n1+n2). MI=max(0,(171-5.2*ln(V)-0.23*CC-16.2*ln(LOC))*100/171), no comment term. CBO=distinct project-defined type names referenced syntactically. LCOM4=connected components of instance methods sharing instance fields/primary constructor dependencies or directly calling each other; constructors/static methods excluded.",
    Results = results
}, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine(output);
return 0;

static MethodMetric AnalyzeMethod(MethodDeclarationSyntax method, SyntaxTree tree)
{
    SyntaxNode body = (SyntaxNode?)method.Body ?? (SyntaxNode?)method.ExpressionBody?.Expression ?? method;
    var nodes = body.DescendantNodesAndSelf().ToArray();
    var decisions = nodes.Where(n => n is IfStatementSyntax or ForStatementSyntax or ForEachStatementSyntax
        or WhileStatementSyntax or DoStatementSyntax or CatchClauseSyntax or CaseSwitchLabelSyntax
        or CasePatternSwitchLabelSyntax or ConditionalExpressionSyntax or ConditionalAccessExpressionSyntax
        || n.IsKind(SyntaxKind.LogicalAndExpression) || n.IsKind(SyntaxKind.LogicalOrExpression)
        || n.IsKind(SyntaxKind.CoalesceExpression)).Select(n => n.Kind().ToString()).ToArray();
    var switchExpressions = nodes.OfType<SwitchExpressionSyntax>().Sum(s => Math.Max(0, s.Arms.Count - 1));
    var cc = 1 + decisions.Length + switchExpressions;
    var tokens = body.DescendantTokens().Where(t => !t.IsMissing).ToArray();
    var loc = tokens.Where(t => !t.IsKind(SyntaxKind.OpenBraceToken) && !t.IsKind(SyntaxKind.CloseBraceToken))
        .Select(t => tree.GetLineSpan(t.Span).StartLinePosition.Line).Distinct().Count();
    bool Delimiter(SyntaxToken t) => t.Kind() is SyntaxKind.OpenBraceToken or SyntaxKind.CloseBraceToken
        or SyntaxKind.OpenParenToken or SyntaxKind.CloseParenToken or SyntaxKind.OpenBracketToken
        or SyntaxKind.CloseBracketToken or SyntaxKind.CommaToken or SyntaxKind.SemicolonToken;
    bool Operand(SyntaxToken t) => t.IsKind(SyntaxKind.IdentifierToken) || t.Parent is LiteralExpressionSyntax
        || t.Kind() is SyntaxKind.InterpolatedStringTextToken;
    var significant = tokens.Where(t => !Delimiter(t)).ToArray();
    var operands = significant.Where(Operand).Select(t => t.Text).ToArray();
    var operators = significant.Where(t => !Operand(t)).Select(t => t.Text).ToArray();
    var n1 = operators.Distinct().Count();
    var n2 = operands.Distinct().Count();
    var volume = (operators.Length + operands.Length) * Math.Log2(Math.Max(1, n1 + n2));
    var mi = Math.Max(0, (171 - 5.2 * Math.Log(Math.Max(1, volume)) - 0.23 * cc
        - 16.2 * Math.Log(Math.Max(1, loc))) * 100 / 171);
    return new MethodMetric(method.Identifier.ValueText, cc, loc, operators.Length, operands.Length,
        n1, n2, Math.Round(volume, 4), Math.Round(mi, 2), decisions);
}

record MethodMetric(string Method, int CC, int LOC, int TotalOperators, int TotalOperands, int UniqueOperators, int UniqueOperands, double Volume, double MI, string[] Decisions);
