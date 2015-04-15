using System;
using System.Collections.Generic;

namespace WebApiOAuthTest
{
    public static class UserRepo
    {
        private static readonly Dictionary<string, string> _users = new Dictionary<string, string>();

        public static IReadOnlyDictionary<string, string> Users { get { return _users; }}

        public static void RegisterUser(string userName, string password)
        {
            if(_users.ContainsKey(userName))
                throw new InvalidOperationException("User already exists");

            _users.Add(userName, password);
        }
    }
}
