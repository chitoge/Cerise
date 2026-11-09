package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "path/filepath"

    "go.fuchsia.dev/fuchsia/tools/fidl/lib/fidlgen"
    "go.fuchsia.dev/fuchsia/zircon/tools/zither"
    "go.fuchsia.dev/fuchsia/zircon/tools/zither/backends/kernel"
)

var flags struct {
    irFile         string
    outputManifest string
    outputDir      string
    sourceDir      string
}

func init() {
    flag.StringVar(&flags.irFile, "ir", "", "The FIDL IR JSON file to process.")
    flag.StringVar(&flags.outputManifest, "output-manifest", "", "A path for the JSON output manifest.")
    flag.StringVar(&flags.outputDir, "output-dir", "", "The directory under which generated files will be written.")
    flag.StringVar(&flags.sourceDir, "source-dir", ".", "The source root used to relativize FIDL filenames.")
}

func main() {
    flag.Parse()

    if flags.irFile == "" {
        fatalf("-ir is required")
    }

    outputDir := flags.outputDir
    if outputDir == "" {
        cwd, err := os.Getwd()
        if err != nil {
            fatalf("determine working directory: %v", err)
        }
        outputDir = cwd
    }

    sourceDir := filepath.Clean(flags.sourceDir)

    absOutputDir, err := filepath.Abs(outputDir)
    if err != nil {
        fatalf("resolve output directory %q: %v", outputDir, err)
    }

    ir, err := fidlgen.ReadJSONIr(flags.irFile)
    if err != nil {
        fatalf("read IR: %v", err)
    }

    gen := kernel.NewGenerator(fidlgen.NewFormatter(""))
    summary, err := zither.Summarize(ir, sourceDir, gen.DeclOrder(), gen.DeclCallback)
    if err != nil {
        fatalf("summarize IR: %v", err)
    }

    outputs, err := gen.Generate(*summary, absOutputDir)
    if err != nil {
        fatalf("generate kernel outputs: %v", err)
    }

    if flags.outputManifest != "" {
        if err := writeManifest(flags.outputManifest, outputs); err != nil {
            fatalf("write manifest: %v", err)
        }
    }
}

func writeManifest(path string, outputs []string) error {
    file, err := os.Create(path)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    return encoder.Encode(outputs)
}

func fatalf(format string, args ...any) {
    fmt.Fprintf(os.Stderr, format+"\n", args...)
    os.Exit(1)
}