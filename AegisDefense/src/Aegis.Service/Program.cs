using System.ServiceProcess;

namespace Aegis.Service;

public static class Program
{
    public static void Main(string[] args)
    {
        if (Environment.UserInteractive || args.Contains("--console"))
        {
            RunAsConsole();
        }
        else
        {
            ServiceBase.Run(new AegisWindowsService());
        }
    }

    /// <summary>Lets a developer run <c>AegisDefenseService.exe --console</c> (elevated) to see logs directly and Ctrl+C to stop, instead of installing the service for every iteration.</summary>
    private static void RunAsConsole()
    {
        Console.WriteLine("Aegis Defense Service - running in console mode (Ctrl+C to stop).");
        var host = new ServiceHost();

        var stopSignal = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stopSignal.Set();
        };

        host.StartAsync().GetAwaiter().GetResult();
        stopSignal.Wait();
        host.Stop();
    }
}
