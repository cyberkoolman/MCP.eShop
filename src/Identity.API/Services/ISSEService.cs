public interface ISSEService
{
    Task AddClient(string clientId, HttpResponse response);
    Task RemoveClient(string clientId);
    Task BroadcastToAll(string eventType, object data);
    Task<bool> SendToClient(string clientId, string eventType, object data);
    Task NotifyCommandExecution(string command, string source, object result);
}
