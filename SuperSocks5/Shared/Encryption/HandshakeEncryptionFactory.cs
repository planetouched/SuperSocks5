using SuperSocks5.Shared.Encryption._Base;
using SuperSocks5.Shared.Encryption.None;
using SuperSocks5.Shared.Encryption.Xor;

namespace SuperSocks5.Shared.Encryption
{
    public class HandshakeEncryptionFactory
    {
        public static HandshakeEncryptionBase Detect(byte id)
        {
            if (NoHandshakeEncryption.Detect(id))
            {
                return new NoHandshakeEncryption();
            }
            
            if (XorHandshakeEncryption.Detect(id))
            {
                return new XorHandshakeEncryption();
            }

            Console.WriteLine("No HandshakeEncryption found");
            throw new Exception();
        }
        
        public static HandshakeEncryptionBase Create(string name)
        {
            if (NoHandshakeEncryption.StaticName == name)
            {
                return new NoHandshakeEncryption();
            }
            
            if (XorHandshakeEncryption.StaticName == name)
            {
                return new XorHandshakeEncryption();
            }

            Console.WriteLine("No HandshakeEncryption found");
            throw new Exception();
        }
    }
}
