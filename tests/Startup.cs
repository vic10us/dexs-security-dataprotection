using System;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit.Abstractions;
using Xunit.DependencyInjection;

namespace DEXS.Security.DataProtection.Tests
{
    public class Startup : DependencyInjectionTestFramework
    {
        public Startup(IMessageSink messageSink) : base(messageSink) { }

        protected void ConfigureServices(IServiceCollection services)
        {
            services.AddDataProtectionServices(config =>
            {
                config.ApplicationName = "SecretService";
                config.ConnectionString = "Path=./keys;";
                config.KeyLifeTime = TimeSpan.FromDays(14);
                config.Type = DataProtectionPersistenceType.FileSystem;
            });
        }

        protected override IHostBuilder CreateHostBuilder(AssemblyName assemblyName) =>
            base.CreateHostBuilder(assemblyName)
                .ConfigureServices(ConfigureServices);
    }
}