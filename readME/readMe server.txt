### Program: chatserver.py
## Author: Paul Siebenaler
## Date: 04/09/024
## Version: 4.4	


#requirements
	python v3.12
	packages*:
		- socket
		- threading
		- os
		- tkinter
		- random
		- sys
		- string
		
	* if you are missing packages then they should be installed using the pip command
		
# Overview:
	This program will host a web server that will allow people to connect and message each
	other through. This program will save users login credentials and encrypt them with a
	self generated key. People connected can send messages to all or to specific individuals.
	Once you are ready to close the server oyu can exit via the exit button.
	
# How To:
	To run this program you must first consider which ip address you want to user. If you are
	hosting this server on the same machine you can keep the default HOST as 'localhost'. After 
	this you must use the command prompt and navigate to the file directory. Once there enter:
		c:\<user dir>\> python chatserver.py <port>
	
	If it is your first time starting the server then 2 new text files will be generated. One
	is labeled Key_file and the other is Save_file. These two files will hold the encrypted 
	user credentials and the key used to encrypt/decrypt text. If you have these files present
	than the server will read the users stored there and begin listening for users trying to
	connect.
	
	Once users are connected the admin does not need to do anything. People will connect automatically
	and the server will save every time a new user connects. Once the server is finished you can shutdown
	the server by selecting the exit button. This will send each connected client a special message which
	will disconnect the user and disable their ability click their buttons.
	
	Every time the server closes it will save the users once last time and terminate.
	
	*NOTE if you are missing either the key or save file you must remove both and restart the server
	the users credentials will be deleted, but without a key they are lost anyway.
	
# Examples:
	see attached main.pdf
###