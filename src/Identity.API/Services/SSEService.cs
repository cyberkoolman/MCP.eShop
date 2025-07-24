using System.Collections.Concurrent;
using System.Text;

public class SSEService : ISSEService
{
    private readonly ConcurrentDictionary<string, SSEClient> _clients = new();
    private readonly ILogger<SSEService> _logger;

    public SSEService(ILogger<SSEService> logger)
    {
        _logger = logger;
    }

    public async Task AddClient(string clientId, HttpResponse response)
    {
        var client = new SSEClient
        {
            Id = clientId,
            Response = response,
            ConnectedAt = DateTime.UtcNow
        };
        
        _clients.TryAdd(clientId, client);
        _logger.LogInformation($"Added SSE client: {clientId}");
        
        // Send initial connection event
        await SendToClient(clientId, "connected", new { clientId, timestamp = DateTime.UtcNow });
    }

    public async Task RemoveClient(string clientId)
    {
        if (_clients.TryRemove(clientId, out var client))
        {
            _logger.LogInformation($"Removed SSE client: {clientId}");
            await Task.CompletedTask;
        }
    }

    public async Task BroadcastToAll(string eventType, object data)
    {
        var tasks = _clients.Values.Select(client => SendToClientInternal(client, eventType, data));
        await Task.WhenAll(tasks);
        _logger.LogInformation($"Broadcasted event '{eventType}' to {_clients.Count} clients");
    }

    public async Task<bool> SendToClient(string clientId, string eventType, object data)
    {
        if (_clients.TryGetValue(clientId, out var client))
        {
            await SendToClientInternal(client, eventType, data);
            return true;
        }
        return false;
    }

    public async Task NotifyCommandExecution(string command, string source, object result)
    {
        var eventData = new
        {
            command,
            source,
            result,
            timestamp = DateTime.UtcNow,
            executionId = Guid.NewGuid().ToString()
        };

        await BroadcastToAll("command_executed", eventData);
    }

    private async Task SendToClientInternal(SSEClient client, string eventType, object data)
    {
        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(data);
            var eventData = $"event: {eventType}\ndata: {json}\n\n";
            var bytes = Encoding.UTF8.GetBytes(eventData);
            
            await client.Response.Body.WriteAsync(bytes);
            await client.Response.Body.FlushAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning($"Failed to send SSE event to client {client.Id}: {ex.Message}");
            // Remove disconnected client
            await RemoveClient(client.Id);
        }
    }
}

public class SSEClient
{
    public string Id { get; set; } = string.Empty;
    public HttpResponse Response { get; set; } = null!;
    public DateTime ConnectedAt { get; set; }
}