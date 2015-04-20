using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNet.Identity;

namespace WebApiOAuthTest.DAL
{
    public static class UserRepo
    {
        private static readonly IList<User> Users = new List<User>
        {
            new User{UserName = "Admin", Password = "Admin123!"}
        };

        public static void RegisterUser(string userName, string password)
        {
            Users.Add(new User{UserName = userName, Password = password});
        }

        public static bool ValidateLogin(string userName, string password)
        {
            return Users.Any(q => q.Password == password && q.UserName == userName);
        }

        public static User ValidateLogin(UserLoginInfo login)
        {
            return Users.SingleOrDefault(u => u.ExternalProviders
                .Any(q => q.LoginProvider == login.LoginProvider && q.ProviderKey == login.ProviderKey));
        }

        public static void AddLoginAsync(string userName, UserLoginInfo login)
        {
            Users.Single(q => q.UserName == userName).ExternalProviders
                .Add(new ExternalProvider {LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey});
        }
    }
}
