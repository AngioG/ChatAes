using Server_Socket;
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;

class Server
{
    private static int incrementingId = 0;

    static int port = 8888;
    static TcpListener server = null;
    static IPAddress localAddr = IPAddress.Parse("127.0.0.1");
    private static List<Utente> clients = new List<Utente>();

    static void Main(string[] args)
    {
        try
        {
            // Istanzia TcpListener e avvia il server sull'indirizzo e la porta specificati
            server = new TcpListener(localAddr, port);
            server.Start();
            Console.WriteLine("Il server è in attesa di connessioni...");

            // Loop che permette di gestire più client contemporaneamente
            while (true)
            {
                // Accetta la connessione del client
                TcpClient client = server.AcceptTcpClient();
                incrementingId += 1;
                Utente u = null;
                try
                {
                    u = new Utente(client, incrementingId);
                }
                catch (Exception ex)
                {
                    //In caso di errore nella connessione disconnette il client
                    Console.WriteLine($"Errore nella connessione del client {incrementingId}");
                    u.Dispose();
                }

                if (u != null)
                {
                    //Istanzia un nuovo thread per gestire la comunicazione
                    Thread t = new Thread(new ParameterizedThreadStart(HandleClient));
                    t.Start(u);
                    Console.WriteLine($"Inizio configurazione di un nuovo client con id {u.Id}");
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Errore: " + e);
        }
        finally
        {
            // Chiude il server
            if (server != null)
            {
                server.Stop();
            }
        }
    }

    static void HandleClient(object obj)
    {
        bool success = true;

        // Ottiene il client dalla lista degli oggetti passati come argomento del metodo
        var utente = (Utente)obj;

        // Istanzia un oggetto NetworkStream per la comunicazione con il client
        NetworkStream inStream = utente.Client.GetStream();

        // Buffer per la lettura dei dati dal client
        byte[] bytes = new byte[2048];
        int bytesRead;

        //Imposta username e chiave
        bytesRead = 0;
        try
        {
            bytesRead = inStream.Read(bytes, 0, bytes.Length);
        }
        catch
        {
            Console.WriteLine("Un client si è disconnesso");
            clients.Remove(utente);
            utente.Dispose();
        }
        string impostazioni = System.Text.Encoding.ASCII.GetString(bytes, 0, bytesRead);


        string usr = impostazioni.Split('&')[0];
        if (usr.StartsWith("-username ") && Utente.NameIsAvailable(usr.Substring(10)))
            utente.Nome = usr.Substring(10);
        else
            success = false;


        string key = impostazioni.Split('&')[1];
        if (key.StartsWith("-key "))
            utente.ImpostaChiave(key.Substring(5));
        else
            success = false;

        if (!success)
        {
            Console.WriteLine($"Errore della configurazione del client {utente.Id}");
            byte[] msg = System.Text.Encoding.ASCII.GetBytes("errore");
            var outStream = utente.Client.GetStream();
            outStream.Write(msg, 0, msg.Length);
            utente.Dispose();
            return;
        }
        else
        {
            Console.WriteLine($"Configurazione del client {utente.Id}, {utente.Nome}, avvenuta con successo");

            clients.Add(utente);
            byte[] msg = System.Text.Encoding.ASCII.GetBytes("successo");
            var outStream = utente.Client.GetStream();
            outStream.Write(msg, 0, msg.Length);
        }

        // Loop infinito per leggere i dati dal client e inviare la risposta
        while (true)
        {
            // Legge i dati dal client
            bytesRead = 0;
            try
            {
                bytesRead = inStream.Read(bytes, 0, bytes.Length);
            }
            catch
            {
                break;
                //continue;
            }

            // Converte il comando in una stringa
            string data = System.Text.Encoding.ASCII.GetString(bytes, 0, bytesRead);
            if (data == "exit")
                break;

            if (!string.IsNullOrEmpty(data))
            {
                Console.WriteLine("Comando: {0}", data);
                //Si invia una prima risposta al client
                var outStream = utente.Client.GetStream();
                byte[] risposta = System.Text.Encoding.ASCII.GetBytes("successo");
                outStream.Write(risposta, 0, risposta.Length);

                if (data == "-b")
                {
                    //Si fa scorrere la lista che contiene gli utenti connessi
                    foreach (var c in clients)
                        if (c != utente)
                        {
                            //Si serializza la chiave pubblica in XML e la si
                            //converte in bytes per inviarla al client
                            risposta = c.pubKeyToBytes();
                            outStream = utente.Client.GetStream();
                            outStream.Write(risposta, 0, risposta.Length);

                            try
                            {
                                //Si attende il messaggio per questo utente
                                bytesRead = inStream.Read(bytes, 0, bytes.Length);
                            }
                            catch
                            {
                                break;
                            }

                            //Si invia il messaggio cifrato
                            outStream = c.Client.GetStream();
                            outStream.Write(bytes, 0, bytesRead);

                            Console.WriteLine("Ricevuto: {0}", System.Text.Encoding.ASCII.GetString(bytes));
                        }

                    outStream = utente.Client.GetStream();
                    risposta = System.Text.Encoding.ASCII.GetBytes("finito");
                    outStream.Write(risposta, 0, risposta.Length);
                    Console.WriteLine("Messaggi cifrati inviati");
                }
                else if (data.StartsWith("-usr"))
                {
                    //Viene individuato il destinatario
                    string destinatario = data.Substring(4);
                    var des = clients.Where(c => c.Nome == destinatario).FirstOrDefault();
                    if (des == null)
                    {
                        //Se non c' un utete con il nome indicato si informa il client
                        risposta = System.Text.Encoding.ASCII.GetBytes("errore");
                        outStream.Write(risposta, 0, risposta.Length);
                        continue;
                    }

                    //Se esiste il destinatario si invia al client la sua chiave pubblica
                    risposta = des.pubKeyToBytes();
                    outStream.Write(risposta, 0, risposta.Length);

                    //Si aspetta il messaggio cifrato
                    bytesRead = inStream.Read(bytes, 0, bytes.Length);
                    
                    //Il messaggio viene mostrato, per dimostrare che è cifrato
                    data = System.Text.Encoding.ASCII.GetString(bytes, 0, bytesRead);
                    Console.WriteLine("Ricevuto: {0}", data);

                    //Il messaggio viene inviato al destinatario
                    outStream = des.Client.GetStream();
                    outStream.Write(bytes, 0, bytesRead);
                    Console.WriteLine("Messaggio cifrato inviato");
                }
                else
                {
                    risposta = System.Text.Encoding.ASCII.GetBytes("errore");
                    outStream.Write(risposta, 0, risposta.Length);
                    continue;
                }
            }
        }

        // Chiude la connessione con il client e il thread
        Console.WriteLine("Un client si è disconnesso");
        clients.Remove(utente);
        utente.Dispose();
    }
}
