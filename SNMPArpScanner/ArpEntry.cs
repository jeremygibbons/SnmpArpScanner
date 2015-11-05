using System.Net;
using System.Net.NetworkInformation;

namespace SNMPArpScanner
{
    class ArpEntry
    {
        public IPHostEntry ipEntry { get; }
        public PhysicalAddress physAddress { get; }

        public ArpEntry(IPAddress ip, PhysicalAddress mac)
        {
            ipEntry = new IPHostEntry();
            ipEntry.AddressList = new IPAddress[] { ip };
            physAddress = mac;
        } 
    }
}
