using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Server_Socket
{
    internal class Utente : IDisposable
    {
        private int id;
        public int Id { get => id; }

        private TcpClient client;
        public TcpClient Client { get => client; }

        private string nome;
        public string Nome { get => nome; set { nomiUsati.Add(value); nome = value; } }

        private RSAParameters chiave;
        public RSAParameters Chiave { get => chiave; set { chiave = value; } }

        public void ImpostaChiave(string chiave)
        {
            //get a stream from the string
            var sr = new System.IO.StringReader(chiave);
            //we need a deserializer
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //get the object back from the stream
            Chiave = (RSAParameters)xs.Deserialize(sr);
        }

        private static List<string> nomiUsati { get; } = new List<string>();
        public Utente(TcpClient c, int i)
        {
            id = i;

            if (c == null)
                throw new ArgumentNullException();

            client = c;
        }


        private bool disposedValue;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {

                }
                nomiUsati.Remove(Nome);
                client.Close();
                disposedValue = true;
            }
        }

        ~Utente()
        {
            // Non modificare questo codice. Inserire il codice di pulizia nel metodo 'Dispose(bool disposing)'
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            // Non modificare questo codice. Inserire il codice di pulizia nel metodo 'Dispose(bool disposing)'
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        public byte[] pubKeyToBytes()
        {
            var sw = new System.IO.StringWriter();
            //we need a serializer
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            //serialize the key into the stream
            xs.Serialize(sw, Chiave);
            //get the string from the stream
            var pubKeyString = sw.ToString();
            return System.Text.Encoding.ASCII.GetBytes(pubKeyString);
        }

        public static bool NameIsAvailable(string name)
        {
            if (nomiUsati.Contains(name))
                return false;
            return true;
        }
    }
}
