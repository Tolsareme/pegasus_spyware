using System.Management;

namespace Aegis.Sensor;

/// <summary>Resolves this machine's HostId and a best-effort HostRole classification, used to tag every event and select the right behavioral baseline (doc §7).</summary>
public static class HostIdentity
{
    public static string GetHostId() => Environment.MachineName;

    /// <summary>
    /// Classifies the host role via WMI (ProductType: 1=workstation, 2=domain controller,
    /// 3=server) plus a couple of well-known service checks for finer-grained roles. Falls
    /// back to "Workstation" if WMI is unavailable so the sensor degrades gracefully rather
    /// than failing to start.
    /// </summary>
    public static string GetHostRole()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProductType, Caption FROM Win32_OperatingSystem");
            foreach (ManagementObject os in searcher.Get())
            {
                var productType = Convert.ToInt32(os["ProductType"]);
                if (productType == 2) return "DomainController";
                if (productType == 3) return ClassifyServerRole();
                return "Workstation";
            }
        }
        catch
        {
            // WMI can be locked down or briefly unavailable during boot - never let role
            // classification take the sensor down.
        }
        return "Workstation";
    }

    private static string ClassifyServerRole()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Service WHERE State='Running'");
            var runningServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ManagementObject svc in searcher.Get())
            {
                runningServices.Add((string)svc["Name"]);
            }

            if (runningServices.Contains("MSSQLSERVER") || runningServices.Any(s => s.StartsWith("MSSQL$", StringComparison.OrdinalIgnoreCase)))
                return "SqlServer";
            if (runningServices.Contains("W3SVC")) return "WebServer";
            if (runningServices.Contains("DNS")) return "DnsServer";
            if (runningServices.Contains("DHCPServer")) return "DhcpServer";
        }
        catch
        {
            // Fall through to the generic classification below.
        }
        return "Server";
    }
}
