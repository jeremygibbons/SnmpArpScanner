using CommandLine;
using System.Collections.Generic;

namespace SNMPArpScanner
{
    class CLIOptions
    {
        [Option('f', "file", Required = false, 
            HelpText = "Read targets from file rather than argument")]
        public bool FromFile { get; set; }

        [Option('s', "separator", Required = false, HelpText = "CSV delimiting char to be used when reading files")]
        public string separator { get; set; }

        [Option('c', "community", Default = "public", Required = false,
            HelpText = "SNMPv2 community to be used")]
        public string Community { get; set; }

        [Option('o', "output", Required = false,
            HelpText = "File to write output to, if none default to stdout")]
        public string OutputFileName { get; set; }

        [Option('d', "dns", Required = false, Default = false,
            HelpText = "Attempt to resolve IPs to DNS names")]
        public bool ResolveIPsToHostNames { get; set; }

        [Option('m', "multicast", Required = false, Default = false, 
            HelpText ="include multicast IPs in results")]
        public bool IncludeMulticastIPs { get; set; }

        [Option('b', "broadcast", Required = false, Default = false,
            HelpText = "Include broadcast IPs and MACs")]
        public bool IncludeBroadcastAddresses { get; set; }

        [Value(0, MetaName = "input data",
            HelpText = "Input files to be processed if -f is specified, otherwise targets by IP or hostname.",
            Required = true)]
        public IEnumerable<string> StringSeq { get; set; }

    }
}
