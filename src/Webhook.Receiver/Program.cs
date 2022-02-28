using Serilog;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File($"./logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateBootstrapLogger();

builder.Logging.AddSerilog(Log.Logger);

Log.Information("Starting up");

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapPost("/webhook-receiver", async (HttpContext context) =>
{
    using (StreamReader reader = new(context.Request.Body, Encoding.UTF8))
    {
        var body = await reader.ReadToEndAsync();

        Log.Information(body);

        if (!IsSignatureCompatible(context, "e0c2538a-7562-4571-abee-4240d7242164", body)) // --> if (!IsSignatureCompatible("-TOKEN-", body))
        {
            throw new Exception("Unexpected Signature");
        }
    }
    Results.Ok();
})
.WithName("webhook-receiver");

app.Run();

static bool IsSignatureCompatible(HttpContext context, string secret, string body)
{
    if (!context.Request.Headers.ContainsKey("X-6Storage-webhook-signature")) // -->  if (!HttpContext.Request.Headers.ContainsKey("-KEY-"))
    {
        return false;
    }

    var receivedSignature = context.Request.Headers["X-6Storage-webhook-signature"].ToString().Split("=");

    string computedSignature;

    switch (receivedSignature[0])
    {
        case "sha256": // SHA-256 Cryptographic Hash Algorithm
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            using (var hasher = new HMACSHA256(secretBytes))
            {
                var data = Encoding.UTF8.GetBytes(body);
                computedSignature = BitConverter.ToString(hasher.ComputeHash(data));
            }
            break;
        default:
            throw new NotImplementedException();
    }

    return computedSignature == receivedSignature[1];
}