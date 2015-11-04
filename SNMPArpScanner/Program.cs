using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
//using SnmpSharpNet;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using CommandLine;

namespace SNMPArpScanner
{
    //using ScanResultType = Tuple<IPAddress, IPAddress, IPHostEntry, System.Net.NetworkInformation.PhysicalAddress>;

    class Program
    {
        static void Main(string[] args)
        {

            var result = CommandLine.Parser.Default.ParseArguments<ScanOptions>(args);

            var exitCode = result.MapResult(
                (ScanOptions options) => {
                    ARPScan2(options);
                    return 0;
                },
                errors => {
                    return 1;
                });
        }

        static void ARPScan2(ScanOptions options)
        {
            ScanTarget(null, options);
            Console.ReadLine();
        }

        static List<ArpEntry> ScanTarget(IPAddress ip, ScanOptions options)
        {
            List<ArpEntry> results = new List<ArpEntry>();

            OctetString community = new OctetString(options.Community);

            var ARPTypeResult = new List<Variable>();
            Messenger.BulkWalk(VersionCode.V2,
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 161),
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
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 161),
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
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 161),
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

                Console.WriteLine(IPData + " " + mac);
            }

            return results;
        }

     /*   static void ARPScan(CLIOptions options) {
            
            // SNMP community name
            OctetString community = new OctetString(options.Community);

            // Define agent parameters class
            AgentParameters param = new AgentParameters(community);

            // Set SNMP version to 2
            param.Version = SnmpVersion.Ver2;

            List<ScanResultType> results = new List<ScanResultType>();

            if(options.FromFile)
            {
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

                        }
                    }
                }
            }
            else
            {
                foreach(string target in options.StringSeq)
                {
                    IpAddress targetIP = new IpAddress(target);
                    if (targetIP.Valid == false)
                    {
                        //TODO: improve error handling
                        continue;
                    }
                    results.AddRange(ScanTarget(targetIP, param, options.IncludeMulticastIPs));
                    foreach(ScanResultType result in results)
                    {
                        Console.WriteLine("{0} : {1}", result.Item2.ToString(), result.Item4.ToString());
                    }
                }
            }

            Console.ReadLine();
        }

        static List<ScanResultType> ScanTarget(IpAddress ip, AgentParameters agparam, bool includeMulticast)
        {
            // Construct target
            UdpTarget target = new UdpTarget((System.Net.IPAddress) ip, 161, 2000, 0);

            // Define Oid that is the root of the MIB
            //  tree you wish to retrieve
            Oid rootOid = new Oid("1.3.6.1.2.1.4.22");

            // This Oid represents last Oid returned by
            //  the SNMP agent
            Oid lastOid = (Oid)rootOid.Clone();

            // Pdu class used for all requests
            Pdu pdu = new Pdu(PduType.GetNext);

            List<ScanResultType> results = new List<ScanResultType>();

            // Loop through results
            while (lastOid != null)
            {
                // When Pdu class is first constructed, RequestId is set to a random value
                // that needs to be incremented on subsequent requests made using the
                // same instance of the Pdu class.
                if (pdu.RequestId != 0)
                {
                    pdu.RequestId += 1;
                }
                // Clear Oids from the Pdu class.
                pdu.VbList.Clear();
                // Initialize request PDU with the last retrieved Oid
                pdu.VbList.Add(lastOid);
                // Make SNMP request
                // TODO: catch exceptions in the Request
                SnmpV2Packet result;
                try
                {
                    result = (SnmpV2Packet)target.Request(pdu, agparam);
                }
                catch (SnmpSharpNet.SnmpException se)
                {
                    Console.WriteLine(se.Message + ": " + se.ErrorCode);
                    return results;
                }
                // If result is null then agent didn't reply or we couldn't parse the reply.
                if (result != null)
                {
                    // ErrorStatus other then 0 is an error returned by 
                    // the Agent - see SnmpConstants for error definitions
                    if (result.Pdu.ErrorStatus != 0)
                    {
                        // agent reported an error with the request
                        Console.WriteLine("Error in SNMP reply. Error {0} index {1}",
                            result.Pdu.ErrorStatus,
                            result.Pdu.ErrorIndex);
                        lastOid = null;
                        break;
                    }
                    else
                    {
                        // Walk through returned variable bindings
                        foreach (Vb v in result.Pdu.VbList)
                        {
                            // Check that retrieved Oid is "child" of the root OID
                            if (rootOid.IsRootOf(v.Oid))
                            {
                                lastOid = v.Oid;

                                string[] oidparts = v.Oid.ToString().Split('.');
                                int FirstByte = int.Parse(oidparts[oidparts.Length - 4]);

                                //skip multicast IPs from 224.0.0.0/4
                                if (includeMulticast == false && FirstByte >= 224 && FirstByte <= 239)
                                    continue;

                                string ipstr = String.Join(".", new ArraySegment<String>(oidparts, oidparts.Length - 4, 4));

                                //skip limited broadcast IP per RFC 6890
                                if (ipstr == "255.255.255.255")
                                    continue;

                                IpAddress arpip = new IpAddress(ipstr);
 
                                string m = String.Join("-", v.Value.ToString().ToUpper().Split());

                                //skip broadcast MAC
                                if (m == "FF-FF-FF-FF-FF-FF")
                                    continue;

                                if (m == "00-00-00-00-00-00")
                                    continue;

                                System.Net.NetworkInformation.PhysicalAddress mac;

                                try
                                {
                                    mac = System.Net.NetworkInformation.PhysicalAddress.Parse(m);
                                }
                                catch (FormatException fe)
                                {
                                    Console.WriteLine("Skipping invalid physical address. " + fe.Message);
                                    continue;
                                }

                                results.Add(new ScanResultType((IPAddress) ip, (IPAddress) arpip, null, mac));
                            }
                            else
                            {
                                // we have reached the end of the requested
                                // MIB tree. Set lastOid to null and exit loop
                                lastOid = null;
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("No response received from SNMP agent.");
                }
            }
            target.Close();
            return results;
        }
        */
    }
}
