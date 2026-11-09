using System.Security.Cryptography;
using System.Text;

namespace App.Security;

public sealed class DocumentHasher
{
    public string Hash(string content)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(bytes);
    }
}
