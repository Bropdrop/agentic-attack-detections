// Parse KQL with Microsoft's Kusto.Language and check table and column names against schema.json.
//   dotnet run --project tools/kqlcheck -c Release -- tools/kqlcheck/schema.json query1.kql query2.kql ...
// A file may hold several queries separated by blank lines (the Log Analytics editor runs them one at a time).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using Kusto.Language;
using Kusto.Language.Symbols;

class Program
{
    static TypeSymbol TypeOf(string t) => t switch
    {
        "datetime" => ScalarTypes.DateTime, "long" => ScalarTypes.Long, "int" => ScalarTypes.Int, "real" => ScalarTypes.Real,
        "bool" => ScalarTypes.Bool, "boolean" => ScalarTypes.Bool, "dynamic" => ScalarTypes.Dynamic, "guid" => ScalarTypes.Guid,
        "timespan" => ScalarTypes.TimeSpan, _ => ScalarTypes.String,
    };

    static List<string> Check(string text, GlobalState globals, string[] open)
    {
        // Tables with no fixed column list (AzureDiagnostics) get a syntax check only.
        bool syntaxOnly = open.Any(t => Regex.IsMatch(text, @"\b" + t + @"\b"));
        var code = syntaxOnly ? KustoCode.Parse(text) : KustoCode.ParseAndAnalyze(text, globals);
        return code.GetDiagnostics().Where(d => d.Severity == "Error")
            .Select(d => $"line {text.Take(d.Start).Count(c => c == '\n') + 1}: {d.Message}").ToList();
    }

    static int Main(string[] args)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(args[0]));
        var open = doc.RootElement.GetProperty("_open").EnumerateArray().Select(e => e.GetString()).ToArray();
        var members = new List<Symbol>();
        foreach (var table in doc.RootElement.GetProperty("tables").EnumerateObject())
            members.Add(new TableSymbol(table.Name, table.Value.EnumerateObject().Select(c => new ColumnSymbol(c.Name, TypeOf(c.Value.GetString())))));
        // The watchlist the repository ships: feeds/sentinel-watchlist.csv
        members.Add(new FunctionSymbol("_GetWatchlist", "(name:string)",
            "{ datatable(SearchKey:string, value:string, type:string, confidence:string, context:string, actor:string, source:string, source_url:string, reported:string, review_by:string, framework:string)[] }"));
        var globals = GlobalState.Default.WithDatabase(new DatabaseSymbol("workspace", members));

        int bad = 0;
        foreach (var file in args.Skip(1))
        {
            var text = File.ReadAllText(file).Replace("\r\n", "\n");
            var errors = Check(text, globals, open);
            if (errors.Count == 0) continue;
            var parts = Regex.Split(text, @"\n\s*\n").Where(p => p.Split('\n').Any(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith("//"))).ToList();
            var partErrors = parts.SelectMany(p => Check(p, globals, open)
                .Select(e => e + "  [query starting: " + p.Split('\n').First(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith("//")).Trim() + "]")).ToList();
            if (parts.Count > 1 && partErrors.Count == 0) continue;
            bad++;
            Console.WriteLine("ERROR " + file);
            foreach (var e in (parts.Count > 1 && partErrors.Count < errors.Count ? partErrors : errors).Take(8)) Console.WriteLine("  " + e);
        }
        Console.WriteLine($"kql: {args.Length - 1} queries checked, {bad} with errors");
        return bad > 0 ? 1 : 0;
    }
}
