using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using SBERP.Shared.Extensions;
using Serilog;
using System.Net;
using System.Text;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);

// 1. Configuration
// CreateBuilder already loads appsettings.json, appsettings.{Environment}.json, environment variables
// and command-line arguments. Only the Ocelot route files are added here; environment variables and
// command-line arguments are added again after them so they keep the highest priority (a source
// added later wins) — re-adding appsettings.json here would make the file override them.
builder.Configuration
    .AddJsonFile(Path.Combine(builder.Environment.ContentRootPath, "ocelot.json"), optional: false, reloadOnChange: true)
    .AddJsonFile(Path.Combine(builder.Environment.ContentRootPath, $"ocelot.{builder.Environment.EnvironmentName}.json"),
                 optional: true, reloadOnChange: true)
    .AddEnvironmentVariables()
    .AddCommandLine(args);

// 1.1 Azure Key Vault — added LAST so its secrets override appsettings.json.
//     Mirrors the SBERP.Security / SBERP.HumanResources setup. The provider maps
//     "--" in secret names to ":", so the secret "JwtSettings--Key" lands at
//     configuration["JwtSettings:Key"]. Gated by the same IsConnectionStrInAzureVault
//     flag for consistency (rename later if you prefer a JWT-specific flag).
bool useVault = bool.Parse(builder.Configuration["IsConnectionStrInAzureVault"] ?? "false");
var keyVaultUri = builder.Configuration["KeyVaultUri"];

if (useVault && !string.IsNullOrWhiteSpace(keyVaultUri))
{
    builder.Configuration.AddAzureKeyVault(
        new Uri(keyVaultUri),
        new DefaultAzureCredential());
}

// 2. Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .WriteTo.Console()
    .CreateLogger();
builder.Host.UseSerilog();
Log.Information("SBERP.Gateway starting...");

// 3. CORS: browser origins allowed to call the API (AllowedOrigins). The app sends a bearer token,
//    not cookies, so credentials are not allowed.
string[] allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>()
    ?? ["https://localhost:4200", "http://localhost:4200"];
builder.Services.AddCors(options =>
    options.AddPolicy("GatewayCorsPolicy", policy =>
        policy
            .WithOrigins(allowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .WithExposedHeaders("Token-Expired",
                                "X-RateLimit-Limit",
                                "X-RateLimit-Remaining",
                                "X-RateLimit-Reset")));

// 4. JWT Bearer — Layer 1 validation before Ocelot forwards
// Key/Issuer/Audience MUST match SBERP.Security AppSettings:JWT exactly.
// JwtSettings:Key now comes from Key Vault (secret "JwtSettings--Key"); the file
// value is the offline fallback.
var jwtKey = builder.Configuration["JwtSettings:Key"];
var jwtIssuer = builder.Configuration["JwtSettings:Issuer"];
var jwtAudience = builder.Configuration["JwtSettings:Audience"];

if (string.IsNullOrWhiteSpace(jwtKey))
    throw new InvalidOperationException(
        "JwtSettings:Key is missing. Set the Key Vault secret 'JwtSettings--Key' " +
        "or the JwtSettings:Key fallback in SBERP.Gateway appsettings.json.");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer("Bearer", options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.Zero
        };
        options.Events = new JwtBearerEvents
        {
            // Angular interceptor watches "Token-Expired" header to trigger refresh
            OnAuthenticationFailed = ctx =>
            {
                if (ctx.Exception is SecurityTokenExpiredException)
                    ctx.Response.Headers.Append("Token-Expired", "true");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// 4.1 Token blacklist — rejects logged-out tokens and tokens of users whose sessions were ended
//     (password / role change, deactivation) here already, before anything is forwarded.
//     Same Redis keys as the microservices (SBERP.Shared SharedAuthCache).
builder.Services.AddSharedTokenBlacklist();

// 4.2 Rate limits on the anonymous endpoints, per client IP: slows password guessing, token brute
//     force and flooding of the attendance endpoints. Every other route is unlimited here.
int loginPerMinute = builder.Configuration.GetValue("AuthRateLimits:LoginPerMinute", 10);
int refreshPerMinute = builder.Configuration.GetValue("AuthRateLimits:RefreshPerMinute", 30);
// anonymous attendance endpoints: phones (challenge + punch) and door terminals
int mobilePunchPerMinute = builder.Configuration.GetValue("AuthRateLimits:MobilePunchPerMinute", 30);
int devicePushPerMinute = builder.Configuration.GetValue("AuthRateLimits:DevicePushPerMinute", 240);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = (int)HttpStatusCode.TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        // a trailing slash reaches the same route, so it must not reach a different limit
        string path = ctx.Request.Path.Value?.TrimEnd('/').ToLowerInvariant() ?? string.Empty;
        string ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        int? limit = path switch
        {
            "/gateway/auth/authenticateuser" => loginPerMinute,
            "/gateway/auth/refreshtoken" or "/gateway/auth/revoke" => refreshPerMinute,
            "/gateway/hr/attendancepunch/getbiometricchallenge" or "/gateway/hr/attendancepunch/mobilepunch" => mobilePunchPerMinute,
            "/gateway/hr/attendancepunch/devicepunches" or "/iclock/cdata" or "/iclock/getrequest" or "/iclock/devicecmd" => devicePushPerMinute,
            _ => null
        };
        return limit == null
            ? RateLimitPartition.GetNoLimiter("unlimited")
            : RateLimitPartition.GetFixedWindowLimiter($"{path}|{ip}", _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = limit.Value,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            });
    });
});

// 5. Ocelot
builder.Services.AddOcelot(builder.Configuration);

var app = builder.Build();

// 6. Middleware pipeline — order is critical
app.UseSerilogRequestLogging();
app.UseHttpsRedirection();
app.UseRouting();
app.UseCors("GatewayCorsPolicy");
app.UseSecurityHeaders();
app.UseRateLimiter();
app.UseAuthentication();
app.UseTokenBlacklist();
app.UseAuthorization();

// Ocelot handles all routing — replaces app.MapControllers()
await app.UseOcelot();

app.Run();