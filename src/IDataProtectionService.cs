namespace DEXS.Security.DataProtection
{
    public interface IDataProtectionService
    {
        byte[] Protect<T>(T obj);
        string ProtectToString<T>(T obj);
        T UnProtect<T>(byte[] data);
        T UnProtectBase64String<T>(string data);
        byte[] Protect(byte[] data);
        string Protect(string data);
        string UnProtect(string data);
        byte[] UnProtect(byte[] data);
    }
}