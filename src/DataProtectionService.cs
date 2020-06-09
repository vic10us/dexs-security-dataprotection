using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;

namespace DEXS.Security.DataProtection
{
    public class MetaProtector
    {
        public int Index { get; set; }
        public string Purpose { get; set; }
        public IDataProtector Protector { get; set; }

        public MetaProtector()
        {
        }

        public MetaProtector(int index, string purpose, IDataProtector protector)
        {
            Index = index;
            Purpose = purpose;
            Protector = protector;
        }
    }

    public class DataProtectionService : IDataProtectionService
    {
        private IDataProtector Protector => _protectors.LastOrDefault()?.Protector;
        private readonly List<MetaProtector> _protectors = new List<MetaProtector>();
        private readonly IDataProtectionProvider _provider;

        public DataProtectionService(IDataProtectionProvider provider, params string[] purposes)
        {
            var i = 0;
            _provider = provider;
            var purposeBuilder = new StringBuilder();
            foreach (var purpose in purposes)
            {
                purposeBuilder.Append(purposes.Take(i + 1).Aggregate((o, n) => $"{o}:~:{n}"));
                var localProtector =
                    _protectors.LastOrDefault()?.Protector.CreateProtector(purpose)
                    ?? provider.CreateProtector(purpose);
                _protectors.Add(new MetaProtector(i, purposeBuilder.ToString(), localProtector));
                i++;
            }
        }

        public void AddPurpose(string purpose)
        {
            var last = _protectors.LastOrDefault();
            var purposes = _protectors.Select(p => p.Purpose).ToList();
            purposes.Add(purpose);
            var newPurpose = purposes.Aggregate((o, n) => $"{o}:~:{n}");

            var protector = last?.Protector.CreateProtector(purpose) ?? _provider.CreateProtector(purpose);
            _protectors.Add(new MetaProtector((last?.Index ?? -1) + 1, newPurpose, protector));
        }

        public byte[] Protect<T>(T obj)
        {
            return Protect(obj, Protector);
        }

        
        public T UnProtect<T>(byte[] data)
        {
            return UnProtect<T>(data, Protector);
        }

        public string ProtectToString<T>(T obj)
        {
            return Convert.ToBase64String(Protect<T>(obj, Protector));
        }

        public byte[] ProtectScoped(byte[] data)
        {
            var x = _protectors.Select(p => Protect(data, p.Protector)).ToArray();
            return ObjectToByteArray(x);
        }

        public string ProtectScoped(string data)
        {
            var x = _protectors.Select(p => Protect(data, p.Protector)).ToArray();
            return Convert.ToBase64String(ObjectToByteArray(x));
        }

        public byte[] ProtectScoped<T>(T data)
        {
            var x = _protectors.Select(p => Protect<T>(data, p.Protector)).ToArray();
            return ObjectToByteArray(x);
        }

        public T UnProtectBase64String<T>(string data)
        {
            var arr = Convert.FromBase64String(data);
            return UnProtect<T>(arr, Protector);
        }

        private IEnumerable<T> GetUnprotected<T>(byte[][] payloads)
        {
            foreach (var payload in payloads)
            {
                var result = default(T);
                try {
                    result = UnProtect<T>(payload, Protector);
                }
                catch {
                    // ignore error
                }
                if (result != null) yield return result;
            }
        }

        public byte[] UnProtectScoped(byte[] data)
        {
            var payloads = ByteArrayObjectTo<byte[][]>(data);
            var result = GetUnprotected<byte[]>(payloads).FirstOrDefault();
            if (result == null) throw new Exception("Error un-protecting scoped resource for any of the provided purposes");
            return result;
        }

        public T UnProtectScoped<T>(byte[] data)
        {
            var payloads = ByteArrayObjectTo<byte[][]>(data);
            var result = GetUnprotected<T>(payloads).FirstOrDefault();
            if (result == null) throw new Exception("Error un-protecting scoped resource for any of the provided purposes");
            return result;
        }

        public byte[] Protect(byte[] data)
        {
            return Protect(data, Protector);
        }

        public string Protect(string data)
        {
            return Protect(data, Protector);
        }

        public string UnProtect(string data)
        {
            return UnProtect(data, Protector);
        }

        public byte[] UnProtect(byte[] data)
        {
            return UnProtect(data, Protector);
        }

        private static byte[] Protect<T>(T obj, IDataProtector protector)
        {
            var ms = new MemoryStream();
            using (var streamWriter = new StreamWriter(ms))
            using (var writer = new JsonTextWriter(streamWriter))
            {
                var serializer = new JsonSerializer();
                serializer.Serialize(writer, obj);
                writer.Flush();
            }

            return protector.Protect(ms.ToArray());
        }

        private static T UnProtect<T>(byte[] data, IDataProtector protector)
        {
            var bson = UnProtect(data, protector);
            var ms = new MemoryStream(bson);

            using (var reader = new StreamReader(ms))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var ser = new JsonSerializer();
                return ser.Deserialize<T>(jsonReader);
            }
        }

        private static byte[] ObjectToByteArray<T>(T o)
        {
            var binFormatter = new BinaryFormatter();
            var mStream = new MemoryStream();
            binFormatter.Serialize(mStream, o);
            return mStream.ToArray();
        }

        private static T ByteArrayObjectTo<T>(byte[] data)
        {
            var mStream = new MemoryStream();
            var binFormatter = new BinaryFormatter();

            // Where 'objectBytes' is your byte array.
            mStream.Write(data, 0, data.Length);
            mStream.Position = 0;

            var myObject = (T)binFormatter.Deserialize(mStream);
            return myObject;
        }

        private static byte[] Protect(byte[] data, IDataProtector protector)
        {
            return protector.Protect(data);
        }

        private static string Protect(string data, IDataProtector protector)
        {
            return protector.Protect(data);
        }

        private static string UnProtect(string data, IDataProtector protector)
        {
            return protector.Unprotect(data);
        }

        private static byte[] UnProtect(byte[] data, IDataProtector protector)
        {
            return protector.Unprotect(data);
        }

    }
}