namespace FullOAuth.ExternalAuthorization
{
    public class ExternalUserLoginInfo
    {
        public ExternalUserLoginInfo(string loginProvider, string providerKey)
        {
            LoginProvider = loginProvider;
            ProviderKey = providerKey;
        }

        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }
    }
}
