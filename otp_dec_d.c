#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#define bufferSize 256000
char decryptedText[bufferSize];

//Receives data until it reaches terminating symbol @@ and then sends confirmation
//that it is done receiving
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

//Sends data until no bytes are left and then waits for a confirmation from the client that it is done receiving
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

//Strips out terminating symbol @@
void stripTermination(char msg[])
{
	int msgLength = (int)strlen(msg);
	msg[msgLength-1] = 0;
	msg[msgLength-2] = 0;
}

//Decrypts the encrypetd string
void decryptString(char cipher[], char key[])
{
	int i;
	int decryptedChar;
	int cipherVal, keyVal;
	char chars[28] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
	
	for(i = 0; i < (int)strlen(cipher); i++)
	{
		if (cipher[i] == ' ')
		{
			cipherVal = 26;
		}
		else
		{
			cipherVal = cipher[i] - 65;
		}
		
		if (key[i] == ' ')
		{
			keyVal = 26;
		}
		else
		{
			keyVal = key[i] - 65;
		}
		
		decryptedChar = cipherVal - keyVal;
		while (decryptedChar < 0)
		{
			decryptedChar += 27;
		}
		decryptedChar = decryptedChar % 27;
		decryptedText[i] = chars[decryptedChar];
	}
}

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead, charsWritten;
	socklen_t sizeOfClientInfo;
	char plainText[bufferSize];
	char keyText[bufferSize];
	struct sockaddr_in serverAddress, clientAddress;
	char type[5];
	int spawnpid;
	char dec[10];
	char enc[10];
	strcpy(dec, "yes@@");
	strcpy(enc, "no@@");

	//Checking for proper command args
	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0)
	{
		fprintf(stderr, "ERROR opening socket"); 
		exit(1);
	}

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
	{
		fprintf(stderr, "Error: Cannot connect to socket"); 
		exit(1);
	}
	
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	// Accept a connection, blocking if one is not available until one connects
	sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
	
	while(1)
	{
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		
		if (establishedConnectionFD < 0)
		{
			fprintf(stderr, "ERROR on accept\n");
			exit(1);
		}
	
		// Get the message from the client and display it
		memset(plainText, '\0', bufferSize);
		memset(keyText, '\0', bufferSize);
		memset(decryptedText, '\0', bufferSize);
		
		spawnpid = fork();
		
		if(spawnpid < 0)
		{
			fprintf(stderr, "Error: Failed fork\n");
			exit(1);
		}
		else if (spawnpid > 0)
		{
			close(establishedConnectionFD);
			continue;
		}
		else
		{
			//get type to confirm correct process
			charsRead = recvAll(establishedConnectionFD, type);
			
			if (charsRead < 0)
			{
				fprintf(stderr, "Error: Failed to read from client"); 
				exit(1);
			}
			
			stripTermination(type);
			
			//Checks for correct client type and sends positive/negative response
			if(strcmp(type, "d") != 0)
			{
				sendAll(establishedConnectionFD, enc, strlen(enc));
				exit(0);
			}
			else
			{
				sendAll(establishedConnectionFD, dec, strlen(dec));
				exit(0);
			}
			
			//Reads cipher
			charsRead = recvAll(establishedConnectionFD, plainText); // Read plaintext from socket
			
			//Checks for valid read
			if (charsRead < 0)
			{
				fprintf(stderr, "Error: Failed to read from client"); 
				exit(1);
			}
			
			//Reads key text file
			charsRead = recvAll(establishedConnectionFD, keyText); // Read key text from socket
			if (charsRead < 0)
			{
				fprintf(stderr, "Error: Failed to read from client"); 
				exit(1);
			}
			
			//Stripping terminating symbols
			stripTermination(plainText);
			stripTermination(keyText);
			
			//decrypting sring
			decryptString(plainText, keyText);
			
			//adding terminating symbol prior to transmission to client
			strcat(decryptedText, "@@");
			
			//sends decrypted text ot client
			charsWritten = sendAll(establishedConnectionFD, decryptedText, strlen(decryptedText));
			
			close(establishedConnectionFD); // Close the existing socket which is connected to the client
			close(listenSocketFD); // Close the listening socket
			exit(0);
		}
	}

return 0; 
}
