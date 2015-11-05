using CommandLine;
using System.Collections.Generic;

namespace SNMPArpScanner
{
    class ScanOptions
    {
        [Option('f', "file", Required = false, 
            HelpText = "Read targets from file rather than argument")]
        public bool FromFile { get; set; }

        [Option('s', "separator", Required = false, HelpText = "CSV delimiting char to be used when reading files")]
        public string separator { get; set; }

        [Option('c', "community", Default = "public", Required = false,
            HelpText = "SNMPv2 community to be used")]
        public string Community { get; set; }

        [Option('o', "output", Default = "", Required = false,
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

        [Option('D', "dynamic", Required = false, Default = true,
            HelpText = "Process dynamic ARP entries")]
        public bool ProcessDynamicARPEntries { get; set; }

        [Option('S', "static", Required = false, Default = false,
            HelpText = "Process static ARP entries")]
        public bool ProcessStaticARPEntries { get; set; }

        [Option('I', "invalid", Required = false, Default = false,
            HelpText = "Process invalid ARP entries")]
        public bool ProcessInvalidARPEntries { get; set; }

        [Option('O', "other", Required = false, Default = false,
            HelpText = "Process other ARP entries")]
        public bool ProcessOtherARPEntries { get; set; }

        [Value(0, MetaName = "input data",
            HelpText = "Input files to be processed if -f is specified, otherwise targets by IP or hostname.",
            Required = true)]
        public IEnumerable<string> StringSeq { get; set; }

    }
}
