using System.ServiceProcess;
using Aegis.Core.Diagnostics;
using Aegis.Data;
using Aegis.Ipc;
using Aegis.ResponseActions;
using Aegis.Sensor;

namespace Aegis.Service;

/// <summary>Thin ServiceBase shell - all real startup/shutdown logic lives in <see cref="ServiceHost"/> so it can be exercised identically whether run as a real Windows Service or as a console app during development (doc §24 dev-loop convenience).</summary>
public sealed class AegisWindowsService : ServiceBase
{
    private readonly ServiceHost _host = new();

    public AegisWindowsService()
    {
        ServiceName = ServiceConfig.ServiceName;
        CanStop = true;
        CanPauseAndContinue = false;
        AutoLog = true;
    }

    protected override void OnStart(string[] args) => _host.StartAsync().GetAwaiter().GetResult();

    protected override void OnStop() => _host.Stop();
}

/// <summary>Owns the full dependency graph: logger, database, response executor, defense engine, and the IPC server the GUI talks to.</summary>
public sealed class ServiceHost
{
    private IAegisLogger? _logger;
    private AegisDatabase? _db;
    private DefenseEngine? _engine;
    private AegisPipeServer? _pipeServer;

    public async Task StartAsync()
    {
        Directory.CreateDirectory(ServiceConfig.RootDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(ServiceConfig.DatabasePath)!);
        Directory.CreateDirectory(ServiceConfig.LogDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(ServiceConfig.TrustedPolicyPublicKeyPath)!);

        _logger = new RollingFileLogger(ServiceConfig.LogDirectory);
        _logger.Info(nameof(ServiceHost), "Aegis Defense Service starting...");

        _db = AegisDatabase.OpenFile(ServiceConfig.DatabasePath);
        var trustStore = new PolicyTrustStore(ServiceConfig.TrustedPolicyPublicKeyPath, _logger);
        var chainKey = new EventChainKeyStore(ServiceConfig.EventChainKeyPath, _logger).LoadOrCreate();
        var hostId = HostIdentity.GetHostId();
        var responseExecutor = new WindowsResponseExecutor(hostId, _logger);

        _engine = new DefenseEngine(_logger, _db, responseExecutor, trustStore, chainKey);
        await _engine.StartAsync().ConfigureAwait(false);

        var requestHandler = new IpcRequestHandler(_engine, _logger);
        _pipeServer = new AegisPipeServer(
            PipeServerFactory.CreateSecured,
            requestHandler.HandleAsync,
            identifyCaller: pipe => WindowsCallerRoleResolver.Resolve(pipe, _logger));
        _pipeServer.Start();

        _logger.Info(nameof(ServiceHost), "Aegis Defense Service started - control pipe listening.");
    }

    public void Stop()
    {
        _logger?.Info(nameof(ServiceHost), "Aegis Defense Service stopping...");
        _engine?.Stop();
        try { _pipeServer?.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { /* best-effort shutdown */ }
        _db?.Dispose();
        _logger?.Info(nameof(ServiceHost), "Aegis Defense Service stopped.");
    }
}
