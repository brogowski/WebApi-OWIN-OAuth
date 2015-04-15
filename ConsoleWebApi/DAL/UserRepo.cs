using System.Collections.Generic;
using System.Linq;
using FullOAuth.AuthorizationServer.Extensions;
using FullOAuth.DAL.Models;
using FullOAuth.ExternalAuthorization;
using FullOAuth.ExternalAuthorization.Extensions;

namespace ConsoleWebApi.DAL
{
    class UserRepo : IUserAccessValidator, IExternalUserProvider, IExternalUserAccessValidator
    {
        private static readonly IList<UserWithPassword> Users = new List<UserWithPassword>
        {
            new UserWithPassword
            {
                UserName = "Adam",
                Password = "Nowak"
            }
        };

        public bool Validate(string userName, string password)
        {
            return Users.Any(q => q.UserName == userName && q.Password == password);
        }

        public static void RegisterUser(string userName, string password)
        {
            Users.Add(new UserWithPassword { Password = password, UserName = userName });
        }

        public void RegisterUser(string userName)
        {
            Users.Add(new UserWithPassword { UserName = userName });
        }

        public void AddLogin(string userName, ExternalUserLoginInfo login)
        {
            Users.Single(q => q.UserName == userName)
                .ExternalProviders.Add(new ExternalProvider
                {
                    LoginProvider = login.LoginProvider,
                    ProviderKey = login.ProviderKey
                });
        }

        public User ValidateLogin(ExternalUserLoginInfo userLoginInfo)
        {
            return Users.FirstOrDefault(q => q.ExternalProviders
                .Any(p => p.ProviderKey == userLoginInfo.ProviderKey &&
                    p.LoginProvider == userLoginInfo.LoginProvider));
        }

        private class UserWithPassword : User
        {
            public string Password { get; set; }
        }
    }
}
