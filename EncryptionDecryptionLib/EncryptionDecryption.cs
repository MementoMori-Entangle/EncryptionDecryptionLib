using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionDecryptionLib
{
    /// <summary>
    /// 暗号・復号
    /// </summary>
    public class EncryptionDecryption
    {
        /// <summary>
        /// 暗号種別
        /// </summary>
        public enum Type
        {
            /// <summary>
            /// ASE
            /// </summary>
            ASE,

            /// <summary>
            /// RSA
            /// </summary>
            RSA
        };

        /// <summary>
        /// AES IV
        /// </summary>
        const string AES_IV = "pf69DL7GrWFyZcMK";

        /// <summary>
        /// AES KEY
        /// </summary>
        const string AES_KEY = "9Fix4L7HB4PKeKWY";

        /// <summary>
        /// AES CBC
        /// </summary>
        public const string AES_CBC = "CBC";

        /// <summary>
        /// AES ECB
        /// </summary>
        public const string AES_ECB = "ECB";

        /// <summary>
        /// AES OFB
        /// </summary>
        public const string AES_OFB = "OFB";

        /// <summary>
        /// AES CFB
        /// </summary>
        public const string AES_CFB = "CFB";

        /// <summary>
        /// AES CTS
        /// </summary>
        public const string AES_CTS = "CTS";

        /// <summary>
        /// 空白
        /// </summary>
        public const string BLANK = "";

        /// <summary>
        /// AES Key Size
        /// </summary>
        public const int AES_KEY_SIZE = 128;

        /// <summary>
        /// AES Block Size
        /// </summary>
        public const int AES_BLOCK_SIZE = 128;

        /// <summary>
        /// RSA Key Size
        /// </summary>
        public const int RSA_KEY_SIZE = 1024;

        /// <summary>
        /// 0
        /// </summary>
        public const int ZERO = 0;

        /// <summary>
        /// AES IV
        /// </summary>
        public string IvAES { get; set; }

        /// <summary>
        /// AES Key
        /// </summary>
        public string KeyAES { get; set; }

        /// <summary>
        /// AES Key Size
        /// </summary>
        public int KeySizeAES { get; set; }

        /// <summary>
        /// AES Block Size
        /// </summary>
        public int BlockSizeAES { get; set; }

        /// <summary>
        /// AES Mode
        /// </summary>
        public CipherMode ModeAES { get; set; }

        /// <summary>
        /// RSA Key Size
        /// </summary>
        public int KeySizeRSA { get; set; }

        /// <summary>
        /// 公開鍵
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// 秘密鍵
        /// </summary>
        public string PrivateKey { get; set; }

        /// <summary>
        /// 暗号処理
        /// </summary>
        /// <param name="type">種別</param>
        /// <param name="value">値</param>
        /// <returns>暗号値</returns>
        public string Encryption(Type type, string value)
        {
            string result = BLANK;

            switch (type)
            {
                case Type.ASE:
                    result = this.EncryptionAES(value);
                    break;
                case Type.RSA:
                    result = this.EncryptionRSA(value);
                    break;
            }

            return result;
        }

        /// <summary>
        /// 復号処理
        /// </summary>
        /// <param name="type">種別</param>
        /// <param name="value">暗号値</param>
        /// <returns>復号値</returns>
        public string Decrypt(Type type, string value)
        {
            string result = BLANK;

            switch (type)
            {
                case Type.ASE:
                    result = this.DecryptAES(value);
                    break;
                case Type.RSA:
                    result = this.DecryptRSA(value);
                    break;
            }

            return result;
        }

        /// <summary>
        /// バージョンを返す
        /// </summary>
        /// <returns>バージョン</returns>
        public static Version GetVersion()
        {
            System.Reflection.Assembly asm = System.Reflection.Assembly.GetExecutingAssembly();

            return asm.GetName().Version;
        }

        /// <summary>
        /// AES暗号
        /// </summary>
        /// <param name="value">値</param>
        /// <returns>暗号値</returns>
        private string EncryptionAES(string value)
        {
            if (string.IsNullOrEmpty(IvAES))
            {
                IvAES = AES_IV;
            }

            if (string.IsNullOrEmpty(KeyAES))
            {
                KeyAES = AES_KEY;
            }

            if (ZERO >= KeySizeAES)
            {
                KeySizeAES = AES_KEY_SIZE;
            }

            if (ZERO >= BlockSizeAES)
            {
                BlockSizeAES = AES_BLOCK_SIZE;
            }

            byte[] encrypted;

            using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.BlockSize = BlockSizeAES;
                rijndaelManaged.KeySize = KeySizeAES;
                rijndaelManaged.Padding = PaddingMode.PKCS7;
                rijndaelManaged.Mode = ModeAES;
                rijndaelManaged.IV = Encoding.UTF8.GetBytes(IvAES);
                rijndaelManaged.Key = Encoding.UTF8.GetBytes(KeyAES);

                ICryptoTransform encryptor = rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(value);
                        }

                        encrypted = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// RSA暗号
        /// </summary>
        /// <param name="value">値</param>
        /// <returns>暗号値</returns>
        private string EncryptionRSA(string value)
        {
            string result = BLANK;

            if (ZERO >= KeySizeRSA)
            {
                KeySizeRSA = RSA_KEY_SIZE;
            }

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySizeRSA))
            {
                PublicKey = rsa.ToXmlString(false);
                PrivateKey = rsa.ToXmlString(true);

                rsa.FromXmlString(PublicKey);

                byte[] data = Encoding.UTF8.GetBytes(value);

                data = rsa.Encrypt(data, false);

                result = Convert.ToBase64String(data);
            }

            return result;
        }

        /// <summary>
        /// AES復号
        /// </summary>
        /// <param name="value">値</param>
        /// <returns>復号値</returns>
        private string DecryptAES(string value)
        {
            string result = BLANK;

            if (string.IsNullOrEmpty(IvAES))
            {
                IvAES = AES_IV;
            }

            if (string.IsNullOrEmpty(KeyAES))
            {
                KeyAES = AES_KEY;
            }

            if (ZERO >= KeySizeAES)
            {
                KeySizeAES = AES_KEY_SIZE;
            }

            if (ZERO >= BlockSizeAES)
            {
                BlockSizeAES = AES_BLOCK_SIZE;
            }

            using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.BlockSize = BlockSizeAES;
                rijndaelManaged.KeySize = KeySizeAES;
                rijndaelManaged.Mode = CipherMode.CBC;
                rijndaelManaged.Padding = PaddingMode.PKCS7;

                rijndaelManaged.IV = Encoding.UTF8.GetBytes(IvAES);
                rijndaelManaged.Key = Encoding.UTF8.GetBytes(KeyAES);

                ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV);

                using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(value)))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            result = streamReader.ReadLine();
                        }
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// RSA復号
        /// </summary>
        /// <param name="value">値</param>
        /// <returns>復号値</returns>
        private string DecryptRSA(string value)
        {
            string result = BLANK;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(PrivateKey);

                byte[] data = Convert.FromBase64String(value);

                data = rsa.Decrypt(data, false);

                result = Encoding.UTF8.GetString(data);
            }

            return result;
        }
    }
}
