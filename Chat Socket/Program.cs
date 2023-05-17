using System;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using static System.Net.Mime.MediaTypeNames;
using System.Runtime.Loader;
using System.Text;

class Program
{
    private static EventWaitHandle stopRead = new ManualResetEvent(initialState: true);
    private static EventWaitHandle stopWrite = new ManualResetEvent(initialState: true);

    private static string username { get; set; }
    private static RSAParameters privateKey { get; set; }
    private static RSAParameters encryptKey { get; set; }

    private static Regex rgx_utente = new Regex(@"^\w+$",
      RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static Regex rgx_messaggio = new Regex(@"^-(usr|b)\w*:",
          RegexOptions.Compiled | RegexOptions.IgnoreCase);


    private static byte[] modulus =
{
            214,46,220,83,160,73,40,39,201,155,19,202,3,11,191,178,56,
            74,90,36,248,103,18,144,170,163,145,87,54,61,34,220,222,
            207,137,149,173,14,92,120,206,222,158,28,40,24,30,16,175,
            108,128,35,230,118,40,121,113,125,216,130,11,24,90,48,194,
            240,105,44,76,34,57,249,228,125,80,38,9,136,29,117,207,139,
            168,181,85,137,126,10,126,242,120,247,121,8,100,12,201,171,
            38,226,193,180,190,117,177,87,143,242,213,11,44,180,113,93,
            106,99,179,68,175,211,164,116,64,148,226,254,172,147
        };

    private static byte[] exponent = { 1, 0, 1 };

    private static bool esito = true;
    private static bool ended = false;

    static void Main()
    {
        // Creiamo un'istanza di TcpClient
        TcpClient client = new TcpClient();

        client.NoDelay = true;

        // Proviamo a connetterci ad un endopoint, specificando indirizzo IP e porta
        string ip = "127.0.0.1";
        int port = 8888;
        var endpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Parse(ip), port);

        // Connessione al server
        try
        {
            client.Connect(endpoint);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
            client.Close();
            return;
        }

        bool valido;
        do
        {
            valido = true;
            Console.WriteLine("Inserisci il tuo username: ");
            username = Console.ReadLine();
            Match match = rgx_utente.Match(username);

            if (!match.Success)
            {
                valido = false;
                Console.WriteLine("Username non valido");
            }

        } while (!valido);


        string publicKey = GenerateKeyRSA();
        byte[] data = System.Text.Encoding.ASCII.GetBytes($"-username {username}&-key {publicKey}");
        NetworkStream stream = client.GetStream();
        stream.Write(data, 0, data.Length);

        byte[] buffer = new byte[2048];
        int n = stream.Read(buffer, 0, buffer.Length);
        string esitoUsr = System.Text.Encoding.ASCII.GetString(buffer);
        if (esitoUsr.StartsWith("successo"))
        {
            Console.WriteLine("Connessione al server avvenuta con il successo");
            Console.WriteLine("Per inviare ad un utente -usrNome:Messaggio es. '-usrBob:Ciao'");
            Console.WriteLine("Per inviare in broadcast -b:Messaggio es. '-b:Ciao'");
        }
        else
        {
            Console.WriteLine("Errore");
            return;
        }


        Thread t = new Thread(new ParameterizedThreadStart(Read));
        t.Start(stream);

        //I messaggi vengono inviati in un ciclo infinito
        while (true)
        {
            string message = Console.ReadLine();

            //Si può interrompere la comunicazione digitando "exit"
            if (message == "exit")
                break;

            //Viene controllato che il formato del messaggio da inviare sia valido
            Match match = rgx_messaggio.Match(message);
            if (!match.Success)
            {
                Console.WriteLine("Messaggio non valido");
                Console.WriteLine("Per inviare ad un utente -usrNome:Messaggio es. '-usrBob:Ciao'");
                Console.WriteLine("Per inviare in broadcast -b:Messaggio es. '-b:Ciao'");
                continue;
            }

            string command = message.Split(':')[0];
            data = System.Text.Encoding.ASCII.GetBytes(command);
            stream.Write(data, 0, data.Length);

            //Si attende la risposta del server
            stopWrite.Reset();
            stopWrite.WaitOne();

            //Se la risposta ha avuto esito negativo
            if (!esito)
            {
                Console.WriteLine("Qualcosa è andato storto");
                Console.WriteLine("Per inviare ad un utente -usrNome:Messaggio es. '-usrBob:Ciao'");
                Console.WriteLine("Per inviare in broadcast -b:Messaggio es. '-b:Ciao'");
                continue;
            }

            string testo = message.Split(':')[1];
            var frammenti = message.Split(':');

            for (int i = 2; i < frammenti.Length; i++)
            {
                testo += ":";
                testo += frammenti[i];
            }

            //Si permette al thread di leggere la chiave pubblica
            stopRead.Set();
            //Si attende che la chiave venga letta
            stopWrite.Reset();
            stopWrite.WaitOne();
            if (command == "-b")
            {
                //Il ciclo si basa su una globale modificata dal
                //thread in letture
                while(!ended)
                {
                    //viene generata una chiave AES utilizzata solo
                    //per questo messaggio
                    byte[] AESkey = GenerateKeyAES();
                    data = EncryptTextAES(username + ": " + testo, AESkey);
                    stream.Write(data, 0, data.Length);

                    //Si attende un'altra chiave o la conferma di
                    //aver inviato tutti i messaggi
                    stopRead.Set();
                    stopWrite.Reset();
                    stopWrite.WaitOne();
                }
                //Si resetta la globale su cui si basa il ciclo
                ended = false;
            }
            else
            {
                //viene generata una chiave AES utilizzata solo per questo messaggio
                byte[] AESkey = GenerateKeyAES();
                //Il messaggio viene cifrato con la chiave appena generata
                data = EncryptTextAES(username + ": " + testo, AESkey);
                stream.Write(data, 0, data.Length);
                //Si fa ripartire il thread in lettura
                stopRead.Set();
            }
            //Superfluo
            stopRead.Set();
        }
        // Chiusura del socket
        client.Close();
    }

    private static byte[] GenerateKeyAES()
    {
        var rng = new RNGCryptoServiceProvider();

        // Creazione di un array di byte per la chiave
        byte[] key = new byte[16]; // 16 byte corrispondenti a una chiave AES a 128 bit

        // Generazione della chiave casuale
        rng.GetBytes(key);


        return key;
    }

    private static void Read(object obj)
    {
        Stream stream = obj as Stream;

        //La lettura avviene in un ciclo continuo
        while (true)
        {
            byte[] buffer = new byte[2048];
                int n = stream.Read(buffer, 0, 2048);

            if (buffer.Where(c => c == 0).Count() != buffer.Count())
            {
                string messaggio = System.Text.Encoding.ASCII.GetString(buffer);

                if (messaggio.StartsWith("<?xml version"))
                {
                    //La chiave pubblica arriva in formato XML
                    var sr = new System.IO.StringReader(messaggio);
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    //Si imposta il valore di un parametro globale
                    encryptKey = (RSAParameters)xs.Deserialize(sr);
                    //Si fa ripartire il thread che scrive
                    stopWrite.Set();
                    //Si aspetta che l'altro thread invii il messaggio con la chiave corretta
                    stopRead.Reset();
                    stopRead.WaitOne();
                }
                else if (messaggio.StartsWith("successo"))
                {
                    //Si imposta la globale per comunicare all'altro hread che la comunicazione ha avuto successo
                    esito = true;
                    //Si fa ripartire l'altro thread
                    stopWrite.Set();
                    //Si aspetta il thread in lettura, per poi ricevere la chiave dell'utente
                    stopRead.Reset();
                    stopRead.WaitOne();
                }
                else if (messaggio.StartsWith("finito"))
                {
                    ended = true;
                    stopWrite.Set();
                }
                else if (messaggio.StartsWith("errore"))
                {
                    esito = false;
                    stopWrite.Set();
                }
                else
                {
                    //Appena il client riceve un messaggio a lui
                    //destinato scrive il suo contenuto (a
                    //scopo dimostrativo)
                    Console.WriteLine("Messaggio cifrato: "
                        + messaggio);
                    //Il messaggio viene decifrato
                    //I primi 128 byte contengono la chiave
                    //cifrata, mentre is successivi sono
                    //l'effettivo messaggio
                    string response = DecryptTextAES
                        (buffer.Skip(128).ToArray(),
                        buffer.Take(128).ToArray());
                    Console.WriteLine(response);
                }
            }
        }
    }

    private static string GenerateKeyRSA()
    {
        var csp = new RSACryptoServiceProvider();

        //how to get the private key
        privateKey = csp.ExportParameters(true);

        //and the public key ...
        var pubKey = csp.ExportParameters(false);

        //converting the public key into a string representation
        string pubKeyString;

        //we need some buffer
        var sw = new System.IO.StringWriter();
        //we need a serializer
        var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
        //serialize the key into the stream
        xs.Serialize(sw, pubKey);
        //get the string from the stream
        pubKeyString = sw.ToString();

        return pubKeyString;
    }

    public static byte[] DecryptTextRSA(byte[] encryptedText)
    {
        // Creazione di un oggetto RSACryptoServiceProvider
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            //Bisogna importare la chiave privata del client
            rsa.ImportParameters(privateKey);

            // Decifratura della chiave
            byte[] decryptedText = rsa.Decrypt(encryptedText, false);

            //non è necessario eseguire una conversiona
            //perchè la chiave AES deve essere un'array di byte
            return decryptedText;
        }
    }

    public static byte[] EncryptTextRSA(byte[] encryptedText)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            //Questa è la chiave che il client ha ricevuto da server
            rsa.ImportParameters(encryptKey);

            // Cifratura del testo
            encryptedText = rsa.Encrypt(encryptedText, false);
        }

        return encryptedText;
    }

    private static byte[] EncryptTextAES(string plainTextData, byte[] key)
    {
        //Il testo viene convertito da stringa a bytes
        byte[] plaintext = Encoding.ASCII.GetBytes(plainTextData);

        // Vettore di inizializzazione (IV)
        byte[] iv = Encoding.ASCII.GetBytes("0123456789012345");

        byte[] cipherText;

        using (Aes aes = Aes.Create())
        {
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 128;

            aes.Key = key;
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    //Il testo viene cifrato
                    cs.Write(plaintext, 0, plaintext.Length);
                }

                cipherText = ms.ToArray();
            }
        }
        //La chiave AES viene cifrata con la chiave RSA pubblica del mittente
        var cypheredkey = EncryptTextRSA(key);

        //Il messaggio inviato è composto per i primi 128 byte dalla chiave AES cifrata
        //tramite RSA, più il messaggio cifrato tramite AES
        var message = new byte[cypheredkey.Length + cipherText.Length];
        cypheredkey.CopyTo(message, 0);
        cipherText.CopyTo(message, cypheredkey.Length);

        return message;
    }

    private static string DecryptTextAES(byte[] messageBytes, byte[] cryptedKey)
    {
        // Vettore di inizializzazione (IV)
        byte[] iv = Encoding.ASCII.GetBytes("0123456789012345");
        byte[] key = DecryptTextRSA(cryptedKey);

        var a = messageBytes.ToList();//.RemoveAll(b => b == 0);
        var b = a.RemoveAll(b => b == 0);

        // Creazione dell'oggetto AES
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    //Decifra
                    cs.Write(a.ToArray(), 0, a.ToArray().Length);
                }

                var plainText = ms.ToArray();
                return Encoding.ASCII.GetString(plainText);
            }
        }
        // Impostazione della chiave e del vettore di inizializzazio      
    }
}