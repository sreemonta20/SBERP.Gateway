using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using Serilog;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. Load ocelot.json into configuration pipeline
builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json",
                 optional: true, reloadOnChange: true)
    .AddJsonFile("ocelot.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"ocelot.{builder.Environment.EnvironmentName}.json",
                 optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

// 2. Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .WriteTo.Console()
    .CreateLogger();
builder.Host.UseSerilog();
Log.Information("SBERP.Gateway starting...");

// 3. CORS — allow Angular on port 4200
builder.Services.AddCors(options =>
    options.AddPolicy("GatewayCorsPolicy", policy =>
        policy
            .WithOrigins("https://localhost:4200", "http://localhost:4200")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials()
            .WithExposedHeaders("Token-Expired",
                                "X-RateLimit-Limit",
                                "X-RateLimit-Remaining",
                                "X-RateLimit-Reset")));

// 4. JWT Bearer — Layer 1 validation before Ocelot forwards
// Key/Issuer/Audience MUST match SBERP.Security AppSettings:JWT exactly
var jwtKey = builder.Configuration["JwtSettings:Key"];
var jwtIssuer = builder.Configuration["JwtSettings:Issuer"];
var jwtAudience = builder.Configuration["JwtSettings:Audience"];

if (string.IsNullOrWhiteSpace(jwtKey))
    throw new InvalidOperationException(
        "JwtSettings:Key is missing in SBERP.Gateway appsettings.json");

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
                new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtKey)),
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

// 5. Ocelot
builder.Services.AddOcelot(builder.Configuration);

var app = builder.Build();

// 6. Middleware pipeline — order is critical
app.UseSerilogRequestLogging();
app.UseHttpsRedirection();
app.UseRouting();
app.UseCors("GatewayCorsPolicy");
app.UseAuthentication();
app.UseAuthorization();

// Ocelot handles all routing — replaces app.MapControllers()
await app.UseOcelot();

app.Run();