package com.emhcet.netscan;

import picocli.CommandLine;
import picocli.CommandLine.*;
import java.io.File;
import java.util.concurrent.Callable;

@Command(name = "MetaSuggest", version = "MetaSuggest 0.1.0", mixinStandardHelpOptions = true, description = {
        "@|bold,blue 🛰️  MetaSuggest - Metasploit Module Suggester|@",
        "",
        "A fast, flexible, and extensible CLI for suggesting Metasploit modules",
        "based on discovered network services.",
        "",
        "@|italic NetScan always performs live host discovery (ping sweep) before any scan or detection.|@",
        "You can scan a single IP or an entire subnet.",
        "All scans and detections operate only on discovered live hosts.",
        "You must specify which ports and protocols to scan or detect—there are no defaults.",
        "",
        "Features include:",
        "  - TCP/UDP port scanning",
        "  - Service detection",
        "  - Host fingerprinting (OS/vendor/etc)",
        "  - Metasploit module suggestion"
}, footer = {
        "",
        "@|bold EXAMPLES:|@",
        "  metasuggest --input services.json",
        "  metasuggest < services.json",
        "",
        "@|bold OPTIONS:|@",
        "  -i, --input <file>    Input JSON file with discovered services",
        "  -h, --help            Show this help message and exit",
        "  -v, --version         Print version information and exit",
        "",
        "@|italic NOTES:|@",
        "  - Input must be a JSON array of service objects (see docs).",
        "  - Output is a JSON array of Metasploit module suggestions.",
        ""
})
public class App implements Callable<Integer> {

    @Option(names = { "-i", "--input" }, description = "Input JSON file with discovered services")
    private File inputFile;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new App())
                .setColorScheme(CommandLine.Help.defaultColorScheme(CommandLine.Help.Ansi.AUTO))
                .execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        // Here you would invoke the Rust CLI and print its output
        // Example: ProcessBuilder to call suggest_cli with inputFile
        if (inputFile == null) {
            System.err.println("Please specify an input file with -i or --input.");
            return 1;
        }
        ProcessBuilder pb = new ProcessBuilder(
                "../../metasploit_tools/target/debug/suggest_cli",
                inputFile.getAbsolutePath());
        pb.redirectErrorStream(true);
        Process process = pb.start();
        try (var reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        }
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            System.err.println("suggest_cli exited with code " + exitCode);
        }
        return exitCode;
    }
}