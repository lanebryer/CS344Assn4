#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#define bufferSize  128000

//Sends data until no data is left and then waits for confirmation from server
int sendAll(int socket, char msg[], int msgLength)
{
    int remainingBytes = msgLength;
    int bytesSent, total;
    int confirmation;
    char confirmationMsg[3];
    memset(confirmationMsg, '\0', 3);
    
    total = 0;
    
    while (remainingBytes > 0)
    {
        bytesSent = send(socket, msg, msgLength, 0);
        remainingBytes -= bytesSent;
        total += bytesSent;
    }
    
    confirmation = recv(socket, confirmationMsg, 2, 0);
    return total;
}

//Receives data until no data is left and then sends confirmation to server
int recvAll(int socket, char msg[])
{
	int total = 0;
	int current, sent;
	char confirmation[3];
	strcpy(confirmation, "ok");
	char recvChunk[1001];
	do
	{
		memset(recvChunk, '\0', 1001);
		current = recv(socket, recvChunk, 1000, 0);
		total += current;
		strcat(msg, recvChunk);
	}
	while(strstr(msg, "@@") == NULL);
	
	sent = send(socket, confirmation, strlen(confirmation), 0);
	return total;
}

//Strips terminating symbols @@
void stripTermination(char msg[])
{
	int msgLength = (int)strlen(msg);
	msg[msgLength-1] = 0;
	msg[msgLength-2] = 0;
}

void main(int argc, char *argv[])
{
    int socketFD, portNumber, charsWritten, charsRead, i;
    struct sockaddr_in serverAddress;
    struct hostent* serverHostInfo;
    int plainTextFile, keyFile, plainTextSize, keySize;
    char plainText[bufferSize];
    char keyText[bufferSize];
    char fileLength[10];
    char receivedData[bufferSize];
    char type[5] = "d";
    char typeResponse[10];
    
    //checks for proper command arguments
    if (argc != 4)
    {
        fprintf(stderr, "USAGE: %s ciphertext key port\n", argv[0]); 
        exit(1);
    }
    
    //opens text files
    plainTextFile = open(argv[1], O_RDONLY);
    keyFile = open(argv[2], O_RDONLY);
    
    //checks for successful file opens
    if (plainTextFile < 0)
    {
        fprintf(stderr, "Error: failed to open plain text file\n");
        exit(1);
    }
    else if (keyFile < 0)
    {
        fprintf(stderr, "Error: failed to open key file\n");
        exit(1);
    }
    else
    {
        //reads data from files
        plainTextSize = read(plainTextFile, plainText, bufferSize);
        keySize = read(keyFile, keyText, bufferSize);
        
        //Strips out newline
        plainText[strcspn(plainText, "\n")] = 0;
        keyText[strcspn(keyText, "\n")] = 0;
        
        //closes files
        close(plainTextFile);
        close(keyFile);

       //Checks that keysize is >= cipher text file length 
       if (keySize < plainTextSize)
        {
            fprintf(stderr, "Error: Key is shorter than file\n");
            exit(1);
        }
        
        //Checks for bad characters in key file or cipher file
        for (i = 0; i < strlen(plainText); i++)
        {
            if(((int)plainText[i] < 65 && (int)plainText[i] != 32) || (int)plainText[i] > 91)
            {
                fprintf(stderr, "Error: Bad characters in plain text file\n");
                exit(1);
            }
            
            if(((int)keyText[i] < 65 && (int)keyText[i] != 32) || (int)keyText[i] > 90)
            {
                fprintf(stderr, "Error: Bad characters in key file\n");
                exit(1);
            }
        }
    }
    
        //adds terminating symbols before transmission    
        strcat(plainText, "@@");
        strcat(keyText, "@@");
        strcat(type, "@@");
    
    memset((char*)&serverAddress, '\0', sizeof(serverAddress));
    portNumber = atoi(argv[3]);
    
    //Checks for valid port number
    if (portNumber < 0 || portNumber > 65535)
    {
        fprintf(stderr, "Error: invalid port number\n");
        exit(2);
    }
    
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(portNumber);
    serverHostInfo = gethostbyname("localhost");
    
    if (serverHostInfo == NULL)
    {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(1);
    }
    
    memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);
    
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    
    if (socketFD < 0)
    {
        fprintf(stderr, "CLIENT: ERROR opening socket\n");
        exit(1);
    }
    
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
    {
       fprintf(stderr, "CLIENT: ERROR connecting\n");
       exit(1);
    }
        
    //sends client type to server
    charsWritten = sendAll(socketFD, type, strlen(type));
    
    //gets server approval for client type
    charsRead = recvAll(socketFD, typeResponse);
    stripTermination(typeResponse);
    
    //if invalid client type, terminates self
    if(strcmp(typeResponse, "no") == 0)
    {
        fprintf(stderr, "otp_dec cannot connect to that daemon\n");
        raise(SIGTERM);
    }
    
    //sends cipher and key file to server
    charsWritten = sendAll(socketFD, plainText, strlen(plainText));
    charsWritten = sendAll(socketFD, keyText, strlen(keyText));
    
    //gets back decrypted string
    charsRead = recvAll(socketFD, receivedData);
    stripTermination(receivedData);
    
    //prints decrypted string to stdout
    printf("%s\n", receivedData);
    
    close(socketFD);
    exit(0);
}