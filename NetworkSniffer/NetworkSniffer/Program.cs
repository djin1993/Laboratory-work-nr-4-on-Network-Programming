using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;

namespace NetworkSniffer
{
    class Program : IPHeader
    {
        private Socket mainSocket;                          //The socket which captures all incoming packets
        private byte[] byteData = new byte[4096];
        private bool bContinueCapturing = false;



        private void ParseData(byte[] byteData, int nReceived)
        {
           

            //Since all protocol packets are encapsulated in the IP datagram
            //so we start by parsing the IP header and see what protocol data
            //is being carried by it
            IPHeader ipHeader = new IPHeader(byteData, nReceived);

        
            //Now according to the protocol being carried by the IP datagram we parse 
            //the data field of the datagram
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:

                    ipHeader.ShowIP();

                    break;

                case Protocol.UDP:

                    UDPHeader udpHeader = new UDPHeader(ipHeader.IPData,              //IPHeader.Data stores the data being 
                        //carried by the IP datagram
                                                       (int)ipHeader.MessageLength);//Length of the data field                    
                    ipHeader.ShowIP();
                    udpHeader.showUDP();

                    break;

                case Protocol.Unknown:
                    break;
            }

        ;
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mainSocket.EndReceive(ar);

                //Analyze the bytes received...

                ParseData(byteData, nReceived);

                
                
               
                
                    
                if (bContinueCapturing)
                    {
                        byteData = new byte[4096];

                        //Another call to BeginReceive so that we continue to receive the incoming
                        //packets


                        mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                                 new AsyncCallback(OnReceive), null);

                    }
               


            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message, "occured fix errors");
            }
        }
        static void Main(string[] args)
        {

            try
            {
                Program sniffer = new Program();
                if(sniffer.bContinueCapturing==false)
                {
                    //Start capturing the packets...

                    

                    sniffer.bContinueCapturing = true;

                    //For sniffing the socket to capture the packets has to be a raw socket, with the
                    //address family being of type internetwork, and protocol being IP
                    sniffer.mainSocket = new Socket(AddressFamily.InterNetwork,
                        SocketType.Raw, System.Net.Sockets.ProtocolType.IP);
                    IPAddress[] ip = Dns.GetHostAddresses("127.0.0.1");
                    //Bind the socket to the selected IP address
                    sniffer.mainSocket.Bind(new IPEndPoint(ip[0], 0));

                    //Set the socket  options
                    sniffer.mainSocket.SetSocketOption(SocketOptionLevel.IP,            //Applies only to IP packets
                                               SocketOptionName.HeaderIncluded, //Set the include the header
                                               true);                           //option to true

                    byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4] { 1, 0, 0, 0 }; //Capture outgoing packets

                    //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                    sniffer.mainSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                        //of Winsock 2
                                         byTrue,
                                         byOut);
                   

                    //Start receiving the packets asynchronously
                    sniffer.mainSocket.BeginReceive(sniffer.byteData, 0, sniffer.byteData.Length, SocketFlags.None,
                         new AsyncCallback(sniffer.OnReceive), null);
                    
                  
                }

               
            }

            catch (Exception ex)
            {
                Console.WriteLine(ex.Message, "occured fix errors");
            }
            Console.ReadKey();
        
        }
    }
}
     
