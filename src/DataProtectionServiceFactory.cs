using Microsoft.AspNetCore.DataProtection;

namespace DEXS.Security.DataProtection
{
    public class DataProtectionServiceFactory : IDataProtectionServiceFactory
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        public DataProtectionServiceFactory(IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
        }

        public IDataProtectionService CreateInstance(params string[] purposes)
        {
            var result = new DataProtectionService(_dataProtectionProvider, purposes);
            return result;
        }
    }
}