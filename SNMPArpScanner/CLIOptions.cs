using CommandLine;
using System.Collections.Generic;

namespace SNMPArpScanner
{
    class CLIOptions
    {
        [Option('f', "file", Required = false, 
            HelpText = "Read targets from file rather than argument")]
        public bool FromFile { get; set; }

        [Option('c', "community", Default = "public", Required = false,
            HelpText = "SNMPv2 community to be used")]
        public string Community { get; set; }

        [Option('o', "output", Required = false,
            HelpText = "File to write output to, if none default to stdout")]
        public string OutputFileName { get; set; }

        [Value(0, MetaName = "input data",
            HelpText = "Input files to be processed if -f is specified, otherwise targets by IP or hostname.",
            Required = true)]
        public IEnumerable<string> StringSeq { get; set; }

    }
}
