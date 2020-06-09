using System.Collections.Generic;

namespace DEXS.Security.DataProtection
{
    public interface IDataProtectionService
    {
        void AddPurpose(string purpose);

        byte[] Protect(byte[] data);
        string Protect(string data);
        byte[] Protect<T>(T obj);
        string ProtectToString<T>(T obj);

        byte[] ProtectScoped(byte[] data);
        string ProtectScoped(string data);
        byte[] ProtectScoped<T>(T obj);
        
        byte[] UnProtect(byte[] data);
        T UnProtect<T>(byte[] data);
        string UnProtect(string data);
        T UnProtectBase64String<T>(string data);

        byte[] UnProtectScoped(byte[] data);
        T UnProtectScoped<T>(byte[] data);
    }
}