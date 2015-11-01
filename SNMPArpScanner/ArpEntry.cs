using System.Net;
using System.Net.NetworkInformation;

namespace SNMPArpScanner
{
    class ArpEntry
    {
        IPHostEntry ipEntry;
        PhysicalAddress physAddress;

        ArpEntry(IPAddress ip, PhysicalAddress mac)
        {
            ipEntry = new IPHostEntry();
            ipEntry.AddressList = new IPAddress[] { ip };
            physAddress = mac;
        }
    }
}
