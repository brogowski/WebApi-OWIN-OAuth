using System.Collections.Generic;

namespace WebApiOAuthTest.DAL
{
    public class User
    {
        public User()
        {
            ExternalProviders = new List<ExternalProvider>();
        }

        public string UserName { get; set; }
        public string Password { get; set; }
        public IList<ExternalProvider> ExternalProviders { get; private set; }
    }
}
