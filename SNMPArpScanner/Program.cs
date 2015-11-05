using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.IO;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using CommandLine;

namespace SNMPArpScanner
{
    class Program
    {
        static void Main(string[] args)
        {

            var result = CommandLine.Parser.Default.ParseArguments<ScanOptions>(args);

            var exitCode = result.MapResult(
                (ScanOptions options) => {
                    ARPScan(options);
                    return 0;
                },
                errors => {
                    return 1;
                });
        }

        static void ARPScan(ScanOptions options)
        {
            Dictionary<IPAddress, List<ArpEntry>> results = new Dictionary<IPAddress, List<ArpEntry>>();

            IEnumerable<string> targets;

            if (options.FromFile)
            {
                List<string> targetList = new List<string>();
                foreach (string filename in options.StringSeq)
                {
                    using (System.IO.TextReader r = System.IO.File.OpenText(filename))
                    {
                        string s = String.Empty;
                        while ((s = r.ReadLine()) != null)
                        {
                            string[] separators = options.separator == "" ?
                                new string[] { System.Globalization.CultureInfo.CurrentUICulture.TextInfo.ListSeparator } :
                                new string[] { options.separator };
                            string[] lineElts = s.Split(separators, StringSplitOptions.RemoveEmptyEntries);
                            if(lineElts.Length == 1) //IP only
                            {
                                targetList.Add(lineElts[0]);   
                            }
                            else if (lineElts.Length == 2) //Target name,IP
                            {
                                targetList.Add(lineElts[1]);
                            }
                        }
                    }
                }
                targets = targetList;
            }
            else
            {
                targets = options.StringSeq;
            }

            foreach (string target in targets)
            {
                Dictionary<IPAddress, List<ArpEntry>> scanresult = ScanTarget(target, options);
                results = results.Union(scanresult).ToDictionary(k => k.Key, v => v.Value);
            }

            if (options.OutputFileName != "")
            {
                OutputToCSV(results, options);
            }
            else
            {
                foreach (IPAddress ipaddr in results.Keys)
                {
                    foreach (ArpEntry entry in results[ipaddr])
                        Console.WriteLine("On {0}, IP {1} : MAC {2}", ipaddr, entry.ipEntry.AddressList[0], entry.physAddress);
                }
                Console.ReadLine();
            }
        }

        private static void OutputToCSV(Dictionary<IPAddress, List<ArpEntry>> results, ScanOptions options)
        {
            string dir = Path.GetDirectoryName(options.OutputFileName);
            if (dir != "" && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            string separator = string.IsNullOrEmpty(options.separator) ?
                                System.Globalization.CultureInfo.CurrentUICulture.TextInfo.ListSeparator :
                                options.separator ;


            using (var sw = new StreamWriter(options.OutputFileName))
            {
                foreach (IPAddress ipaddr in results.Keys)
                {
                    foreach (ArpEntry entry in results[ipaddr])
                    {
                        sw.WriteLine(String.Join(separator, new object[] { ipaddr, entry.ipEntry.AddressList[0], entry.physAddress }));
                    }
                }
            }
        }

        private static Dictionary<IPAddress, List<ArpEntry>> ScanTarget(string strIP, ScanOptions options)
        {
            IPAddress ip;
            Dictionary<IPAddress, List<ArpEntry>> results = new Dictionary<IPAddress, List<ArpEntry>>();

            try
            {
                IPAddress[] ips = Dns.GetHostAddresses(strIP);
                ip = ips[0];
            }
            catch (Exception e)
            {
                Console.WriteLine("Skipping invalid target {0}: {1}", strIP, e.Message);
                return results;
            }

            results.Add(ip, ScanTarget(ip, options));
            return results;
        }

        static List<ArpEntry> ScanTarget(IPAddress ip, ScanOptions options)
        {
            List<ArpEntry> results = new List<ArpEntry>();

            OctetString community = new OctetString(options.Community);

            var ARPTypeResult = new List<Variable>();
            Messenger.BulkWalk(VersionCode.V2,
                new IPEndPoint(ip, 161),
                new OctetString(options.Community),
                new ObjectIdentifier("1.3.6.1.2.1.4.22.1.4"),
                ARPTypeResult,
                60000,
                10,
                WalkMode.WithinSubtree,
                null,
                null);

            var ARPPhysAddrResult = new List<Variable>();
            Messenger.BulkWalk(VersionCode.V2,
                new IPEndPoint(ip, 161),
                new OctetString(options.Community),
                new ObjectIdentifier("1.3.6.1.2.1.4.22.1.2"),
                ARPPhysAddrResult,
                60000,
                10,
                WalkMode.WithinSubtree,
                null,
                null);

            var ARPIPResult = new List<Variable>();
            Messenger.BulkWalk(VersionCode.V2,
                new IPEndPoint(ip, 161),
                new OctetString(options.Community),
                new ObjectIdentifier("1.3.6.1.2.1.4.22.1.3"),
                ARPIPResult,
                60000,
                10,
                WalkMode.WithinSubtree,
                null,
                null);


            foreach (Variable v in ARPTypeResult)
            {
                if (v.Data.Equals(new Integer32(4)) && options.ProcessStaticARPEntries == false)
                    continue;
                else if (v.Data.Equals(new Integer32(3)) && options.ProcessDynamicARPEntries == false)
                    continue;
                else if (v.Data.Equals(new Integer32(2)) && options.ProcessInvalidARPEntries == false)
                    continue;
                else if (v.Data.Equals(new Integer32(1)) && options.ProcessOtherARPEntries == false)
                    continue;

                uint[] numID = v.Id.ToNumerical().ToArray();

                numID[9] = 3;
                ObjectIdentifier IPID = new ObjectIdentifier(numID);

                ISnmpData IPData = ARPIPResult.Where(i => i.Id == IPID).Select(x => x).Single().Data;

                numID[9] = 2;
                ObjectIdentifier PhysAddrID = new ObjectIdentifier(numID);
                ISnmpData PhysAddrData = ARPPhysAddrResult.Where(i => i.Id == PhysAddrID).Select(x => x).Single().Data;

                System.Net.NetworkInformation.PhysicalAddress mac = new System.Net.NetworkInformation.PhysicalAddress(PhysAddrData.ToBytes().Skip(2).ToArray());

                ArpEntry entry = new ArpEntry(IPAddress.Parse(IPData.ToString()), mac);

                results.Add(entry);
            }

            return results;
        }
    }
}
