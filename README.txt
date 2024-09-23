     Sender Instructions:

1.	Generate RSA Key Pair:
	•	Open the application and go to the Sender tab.
	•	Click on “Generate RSA Key Pair”. This will create a public and private key pair.
	•	Save the public key and share it with the Receiver via a secure method (email, file transfer, etc.). Do not share your private key.
2.	Import Recipient’s Public Key:
	•	Click on the “Browse” button next to “Recipient’s Public Key”.
	•	Select the public key file you received from the Receiver.
3.	Generate Symmetric Key:
	•	Click on “Generate Symmetric Key”. A symmetric AES key will be generated and displayed in the field.
	•	This key will be used to encrypt your file.
4.	Encrypt Symmetric Key with Recipient’s Public Key:
	•	Click on “Encrypt Symmetric Key”.
	•	Choose a location to save the encrypted symmetric key file (e.g., encrypted_key.bin).
	•	This encrypted key file will be sent to the Receiver.
5.	Encrypt the File:
	•	Click on the “Browse” button next to “Input File” to select the file you want to encrypt.
	•	Click on the “Browse” button next to “Encrypted File Output” to choose a location to save the encrypted file.
	•	Click “Encrypt File”. The selected file will be encrypted using the symmetric key.
6.	Send Encrypted Files to Receiver:
	•	Send the following files to the Receiver:
	•	The encrypted file (e.g., encrypted_file.enc).
	•	The encrypted symmetric key file (e.g., encrypted_key.bin).
	•	Use a secure method to transfer these files (e.g., encrypted email, secure file transfer).

     

Receiver Instructions:

1.	Import Your Private Key:
	•	Open the application and go to the Receiver tab.
	•	Click on “Import Private Key” and select your private key file (e.g., private_key.pem).
2.	Import Encrypted Symmetric Key:
	•	Click on the “Browse” button next to “Encrypted Symmetric Key”.
	•	Select the encrypted symmetric key file you received from the Sender (e.g., encrypted_key.bin).
3.	Decrypt the Symmetric Key:
	•	Click on “Decrypt Symmetric Key”.
	•	The decrypted symmetric key will be displayed in the Decrypted Symmetric Key field.
	•	This key will be used to decrypt the encrypted file.
4.	Decrypt the File:
	•	Click on the “Browse” button next to “Encrypted File” to select the encrypted file you received from the Sender (e.g., encrypted_file.enc).
	•	Click on the “Browse” button next to “Decrypted File Output” to choose a location to save the decrypted file.
	•	Click “Decrypt File”. The selected file will be decrypted using the symmetric key.
5.	Access the Decrypted File:
	•	The decrypted file will be saved at the specified location.
	•	You can now access and use the decrypted file as needed
