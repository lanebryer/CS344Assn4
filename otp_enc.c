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

//This function sends data until nothing is left to send and then waits for a confirmation from the server
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

//this function receives data in 1000 byte chunks until it gets the terminating substring @@
//It then sends a confirmation message to the server that it's done receiving
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

//Strips out the terminating symbols @@
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
    char type[5] = "e";
    char typeResponse[5];
    
    if (argc != 4)
    {
        fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]); 
        exit(1);
    }
    
    //Opening the files
    plainTextFile = open(argv[1], O_RDONLY);
    keyFile = open(argv[2], O_RDONLY);
    
    //Checking for successful open
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
        //Reading in data from files
        plainTextSize = read(plainTextFile, plainText, bufferSize);
        keySize = read(keyFile, keyText, bufferSize);
        
        //Removing the newline
        plainText[strcspn(plainText, "\n")] = 0;
        keyText[strcspn(keyText, "\n")] = 0;
        
        //Closing files
        close(plainTextFile);
        close(keyFile);

        
       //Checking that key length >= plain text file length
        if (keySize < plainTextSize)
        {
            fprintf(stderr, "Error: Key is shorter than file\n");
            exit(1);
        }
        
        //Checking for bad characters
        for (i = 0; i < strlen(plainText); i++)
        {
            if(((int)plainText[i] < 65 && (int)plainText[i] != 32) || (int)plainText[i] > 90)
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
    
        //Adding the terminating @@ prior to transmission
        strcat(plainText, "@@");
        strcat(keyText, "@@");
        strcat(type, "@@");
    
    memset((char*)&serverAddress, '\0', sizeof(serverAddress));
    portNumber = atoi(argv[3]);
    
    //Checking for valid port number
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
    
    //Sends client type to the server    
    charsWritten = sendAll(socketFD, type, strlen(type));
    charsRead = recvAll(socketFD, typeResponse);
    stripTermination(typeResponse);
    
    //If server rejects, terminate self
    if(strcmp(typeResponse, "no") == 0)
    {
        fprintf(stderr, "This file cannot connect to that daemon\n");
        raise(SIGTERM);
    }
    
    //Send plain text and key to server
    charsWritten = sendAll(socketFD, plainText, strlen(plainText));
    charsWritten = sendAll(socketFD, keyText, strlen(keyText));
    
    //Reads back encrypted string
    charsRead = recvAll(socketFD, receivedData);
    
    //Removes terminating characters
    stripTermination(receivedData);
    
    //Prints to stdout with a newline
    printf("%s\n", receivedData);
    
    close(socketFD);
    exit(0);
}