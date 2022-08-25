using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Microsoft.DependencyInjection;

namespace DEXS.Security.DataProtection.TestProject.Fixtures;

public class TestFixture : TestBedFixture
{
    protected override void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.AddDataProtectionServices(config =>
        {
            config.ApplicationName = "SecretService";
            config.ConnectionString = "Path=./keys;";
            config.KeyLifeTime = TimeSpan.FromDays(14);
            config.Type = DataProtectionPersistenceType.FileSystem;
        });
        services.AddSingleton<TestDataProvider>(new TestDataProvider());
    }

    protected override ValueTask DisposeAsyncCore() => new();

    protected override IEnumerable<TestAppSettings> GetTestAppSettings()
    {
        yield return new() { Filename = "appsettings.json", IsOptional = false };
    }
}
