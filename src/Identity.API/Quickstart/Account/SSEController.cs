using Microsoft.AspNetCore.Mvc;
using System.Text;

[ApiController]
[Route("api/sse")]
public class SSEController : ControllerBase
{
    private readonly ISSEService _sseService;
    private readonly ILogger<SSEController> _logger;

    public SSEController(ISSEService sseService, ILogger<SSEController> logger)
    {
        _sseService = sseService;
        _logger = logger;
    }

    [HttpGet("events")]
    public async Task StreamEvents(CancellationToken cancellationToken)
    {
        Console.WriteLine("=== SSE Connection Request Received ===");
        Console.WriteLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"Client IP: {HttpContext.Connection.RemoteIpAddress}");

        Response.Headers["Content-Type"] = "text/event-stream";
        Response.Headers["Cache-Control"] = "no-cache";
        Response.Headers["Connection"] = "keep-alive";
        Response.Headers["Access-Control-Allow-Origin"] = "*";
        Response.Headers["Access-Control-Allow-Headers"] = "Cache-Control";

        var clientId = Guid.NewGuid().ToString();
        _logger.LogInformation($"SSE client connected: {clientId}");

        try
        {
            await _sseService.AddClient(clientId, Response);
            
            // Keep connection alive
            while (!cancellationToken.IsCancellationRequested)
            {
                // Send heartbeat every 30 seconds
                await SendEvent("heartbeat", new { timestamp = DateTime.UtcNow, clientId });
                await Task.Delay(30000, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation($"SSE client disconnected: {clientId}");
        }
        finally
        {
            await _sseService.RemoveClient(clientId);
        }
    }

    [HttpPost("broadcast")]
    public async Task<IActionResult> BroadcastEvent([FromBody] EventMessage message)
    {
        await _sseService.BroadcastToAll(message.EventType, message.Data);
        return Ok();
    }

    [HttpPost("send/{clientId}")]
    public async Task<IActionResult> SendToClient(string clientId, [FromBody] EventMessage message)
    {
        var success = await _sseService.SendToClient(clientId, message.EventType, message.Data);
        return success ? Ok() : NotFound();
    }

    private async Task SendEvent(string eventType, object data)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(data);
        var eventData = $"event: {eventType}\ndata: {json}\n\n";
        var bytes = Encoding.UTF8.GetBytes(eventData);
        await Response.Body.WriteAsync(bytes);
        await Response.Body.FlushAsync();
    }
}

public class EventMessage
{
    public string EventType { get; set; } = string.Empty;
    public object Data { get; set; } = new();
}