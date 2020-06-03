using System;

namespace DEXS.Security.DataProtection
{
    public class DataProtectionOptions
    {
        public TimeSpan KeyLifeTime { get; set; } = TimeSpan.FromDays(14);
        public DataProtectionPersistenceType Type { get; set; } = DataProtectionPersistenceType.FileSystem;
        public string ConnectionString { get; set; } = "keys";
    }
}