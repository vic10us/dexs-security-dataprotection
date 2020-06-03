using System;
using System.IO;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using StackExchange.Redis;

namespace DEXS.Security.DataProtection
{
    public static class SecurityExtensions
    {
        public static IDataProtectionBuilder ConfigureDataProtection(this IDataProtectionBuilder builder, DataProtectionOptions options)
        {
            builder.SetDefaultKeyLifetime(options.KeyLifeTime);
            var csBuilder = new System.Data.Common.DbConnectionStringBuilder
            {
                ConnectionString = options.ConnectionString
            };

            switch (options.Type)
            {
                case DataProtectionPersistenceType.FileSystem:
                    builder.PersistKeysToFileSystem(new DirectoryInfo(csBuilder["Path"].ToString()));
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

        public static IServiceCollection AddDataProtectionServices(this IServiceCollection services,
            Action<DataProtectionOptions> options)
        {
            var opt = new DataProtectionOptions();
            options(opt);
            Console.WriteLine(JsonConvert.SerializeObject(opt, Formatting.Indented));
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