using System;

namespace DEXS.Security.DataProtection
{
    public class DataProtectionOptions
    {
        public string ApplicationName { get; set; } = "SecretService";
        public TimeSpan KeyLifeTime { get; set; } = TimeSpan.FromDays(14);
        public DataProtectionPersistenceType Type { get; set; } = DataProtectionPersistenceType.FileSystem;
        public string ConnectionString { get; set; } = "keys";
    }
}