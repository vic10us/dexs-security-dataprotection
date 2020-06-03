namespace DEXS.Security.DataProtection
{
    public interface IDataProtectionServiceFactory
    {
        IDataProtectionService CreateInstance(params string[] purposes);
    }
}