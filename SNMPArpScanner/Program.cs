using System;
using System.Collections.Generic;
using SnmpSharpNet;
using CommandLine;

namespace SNMPArpScanner
{
    using ScanResultType = Tuple<IpAddress, IpAddress, System.Net.NetworkInformation.PhysicalAddress, string>;

    class Program
    {
        static void Main(string[] args)
        {

            var result = CommandLine.Parser.Default.ParseArguments<CLIOptions>(args);

            var exitCode = result.MapResult(
                (CLIOptions options) => {
                    ARPScan(options);
                    return 0;
                },
                errors => {
                    return 1;
                });
        }

        static void ARPScan(CLIOptions options) {
            
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
                    results.AddRange(ScanTarget(targetIP, param));
                }
            }

            Console.ReadLine();
        }

        static List<ScanResultType> ScanTarget(IpAddress ip, AgentParameters agparam)
        {
            // Construct target
            UdpTarget target = new UdpTarget((System.Net.IPAddress) ip, 161, 2000, 0);

            // Define Oid that is the root of the MIB
            //  tree you wish to retrieve
            Oid rootOid = new Oid("1.3.6.1.2.1.3.1.1.2");

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
                                string[] oidparts = v.Oid.ToString().Split('.');
                                string ipstr = String.Join(".", new ArraySegment<String>(oidparts, oidparts.Length - 4, 4));
                                IpAddress arpip = new IpAddress(ipstr);

                                string m = String.Join("-", v.Value.ToString().Split());

                                System.Net.NetworkInformation.PhysicalAddress mac = System.Net.NetworkInformation.PhysicalAddress.Parse(m);

                                System.Net.IPHostEntry host;
                                string dnsname = "";
                                try
                                {
                                    host = System.Net.Dns.GetHostEntry((System.Net.IPAddress) arpip);
                                    dnsname = host.HostName;
                                }
                                catch (System.ArgumentException ae)
                                {
                                    Console.WriteLine("Invalid IP Address: " + ae.Message);
                                }
                                catch (System.Net.Sockets.SocketException se)
                                {
                                    Console.WriteLine("Could not connect to ip " + arpip.ToString() + ". " + se.Message);
                                }

                                results.Add(new ScanResultType(ip, arpip, mac, dnsname));

                                Console.WriteLine("{0} : {1}, {2}",
                                    arpip.ToString(),
                                    mac.ToString(),
                                    dnsname);

                                lastOid = v.Oid;
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
    }
}
