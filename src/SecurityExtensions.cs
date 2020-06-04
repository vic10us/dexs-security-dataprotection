using System;
using System.IO;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace DEXS.Security.DataProtection
{
    public static class SecurityExtensions
    {
        public static IDataProtectionBuilder ConfigureDataProtection(this IDataProtectionBuilder builder, DataProtectionOptions options)
        {
            builder.SetDefaultKeyLifetime(options.KeyLifeTime);
            builder.SetApplicationName(options.ApplicationName);
            var csBuilder = new System.Data.Common.DbConnectionStringBuilder
            {
                ConnectionString = options.ConnectionString
            };

            switch (options.Type)
            {
                case DataProtectionPersistenceType.FileSystem:
                    var dirInfo = new DirectoryInfo(csBuilder["Path"].ToString());
                    builder.PersistKeysToFileSystem(dirInfo);
                    return builder;
                case DataProtectionPersistenceType.Redis:
                {
                    var uri = csBuilder["uri"].ToString();
                    var keystore = csBuilder["keystore"].ToString();
                    if (string.IsNullOrWhiteSpace(keystore)) keystore = "DataProtection-Keys";
                    var redis = ConnectionMultiplexer.Connect(uri);
                    builder.PersistKeysToStackExchangeRedis(redis, keystore);
                    return builder;
                }
                default:
                    throw new ArgumentOutOfRangeException($"No builder present for the specified type: [{options.Type}]");
            }
        }

        public static IServiceCollection AddDataProtectionServices(this IServiceCollection services, Action<DataProtectionOptions> options)
        {
            var opt = new DataProtectionOptions();
            options(opt);
            services.AddDataProtectionServices(opt);
            return services;
        }

        public static IServiceCollection AddDataProtectionServices(this IServiceCollection services, DataProtectionOptions options)
        {
            services.AddDataProtection()
                .ConfigureDataProtection(options);
            services.AddSingleton<IDataProtectionServiceFactory, DataProtectionServiceFactory>();
            return services;
        }
    }
}