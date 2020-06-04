using System;
using System.IO;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;

namespace DEXS.Security.DataProtection
{
    public class DataProtectionService : IDataProtectionService
    {
        private readonly IDataProtector _protector;

        public DataProtectionService(IDataProtectionProvider provider, params string[] purposes)
        {
            _protector = provider.CreateProtector(purposes);
        }

        public byte[] Protect<T>(T obj)
        {
            var ms = new MemoryStream();
            using (var streamWriter = new StreamWriter(ms))
            using (var writer = new JsonTextWriter(streamWriter))
            {
                var serializer = new JsonSerializer();
                serializer.Serialize(writer, obj);
                writer.Flush();
            }
            return Protect(ms.ToArray());
        }

        public T UnProtect<T>(byte[] data)
        {
            var bson = UnProtect(data);
            var ms = new MemoryStream(bson);

            using (var reader = new StreamReader(ms))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var ser = new JsonSerializer();
                return ser.Deserialize<T>(jsonReader);
            }
        }

        public string ProtectToString<T>(T obj)
        {
            return Convert.ToBase64String(Protect(obj));
        }

        public T UnProtectBase64String<T>(string data)
        {
            var arr = Convert.FromBase64String(data);
            return UnProtect<T>(arr);
        }

        public byte[] Protect(byte[] data)
        {
            return _protector.Protect(data);
        }

        public string Protect(string data)
        {
            return _protector.Protect(data);
        }

        public string UnProtect(string data)
        {
            return _protector.Unprotect(data);
        }

        public byte[] UnProtect(byte[] data)
        {
            return _protector.Unprotect(data);
        }

    }
}
