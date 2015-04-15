using System.Collections.Generic;
using System.Linq;
using FullOAuth.DAL;
using FullOAuth.DAL.Models;

namespace ConsoleWebApi.DAL
{
    class RefreshTokenRepo : IRefreshTokenRepo
    {
        private static readonly IList<RefreshToken> Tokens = new List<RefreshToken>();

        public bool AddRefreshToken(RefreshToken token)
        {
            var existingToken = Tokens.SingleOrDefault(q => q.ClientId == token.ClientId && q.Subject == token.Subject);

            if (existingToken != null)
            {
                Tokens.Remove(existingToken);
            }

            Tokens.Add(token);

            return true;
        }

        public RefreshToken FindRefreshToken(string hashedTokenId)
        {
            return Tokens.SingleOrDefault(q => q.Id == hashedTokenId);
        }

        public void RemoveRefreshToken(string hashedTokenId)
        {
            var existingToken = Tokens.SingleOrDefault(q => q.Id == hashedTokenId);

            if (existingToken != null)
            {
                Tokens.Remove(existingToken);
            }
        }
    }
}
