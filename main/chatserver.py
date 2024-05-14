#######################################
#           Server program            #
#-------------------------------------#

"""
chatserver.py for ChatRoom Project
Author: Paul Siebenaler
Date: 04/09/24
Version: 4.4

"""
#-------------------------------------#
#               imports               #
#-------------------------------------#
import socket
import threading
import os
import tkinter
import random
import sys
import string
#-------------------------------------#
#          Global Variables           #
#-------------------------------------#

HOST = 'localhost'
SAVE_FILE = "SAVE_FILE.txt"
KEY_FILE = 'key_file.txt'
banned_users = {} ## {IP_ADDR, uName}
user_list = {} ## ["uName", "password"] << both are stored in an encrypted state
live_users = {} ## {"uName", uSocket} 
EXIT = threading.Event()

#-------------------------------------#
#                 GUI                 #
#-------------------------------------#
"""
admin_gui()
    note: Method will create a new main frame and window and attach a text frame with two buttons.
    This method will be used by the server admin to see what messages are being sent and who
    is trying to connect to the server.

"""

def admin_gui():
    global main, chat_log, save_button, exit_button
    # frame -----------------------
    main = tkinter.Tk()
    main.title('ChatRoom Server')
    # widgets creation -----------------------
    chat_log = tkinter.Text(main,state="disabled", font=('Arial', 16),width = 60, height= 25,wrap=tkinter.WORD,padx=5,pady=5)
    save_button = tkinter.Button(main,text="SAVE", font=('Arial',14), command=save)
    exit_button = tkinter.Button(main, text="EXIT", font=('Arial',14), command=final_close)
    # layout -----------------------
    chat_log.grid(row=0,column=0,columnspan=2)
    save_button.grid(row=1,column=0)
    exit_button.grid(row=1,column=1)
    # method to start listening of new clients connecting
    def server_set():
        try:
            print("Server is listening.... ")
            while not EXIT.is_set():
                new_client, addr = SERVER.accept()
                if not len(live_users) > 20:
                    incoming_users_thread = threading.Thread(target=incoming_users, args=((new_client, addr)))
                    incoming_users_thread.start()
                else:
                    new_client.send('Too many Users active, unable to connect'.encode('utf-8'))
                    new_client.close()
        except Exception as e:
            print(f'Server GUI failure: {e}')
        finally:
            SERVER.close()
    accept_thread = threading.Thread(target=server_set)
    accept_thread.start()
    main.mainloop()
"""
update_chat_log(msg)
    param: string msg
    note: When a message comes in it is received with this method and this will update the chat log
    for the Admin. This is used for seeing chat messages and admin messages
"""  
def update_chat_log(msg):
    if chat_log.winfo_exists():
        chat_log.configure(state='normal')  # Set state to normal to allow editing
        chat_log.insert('end', msg + '\n')  # Insert text at the end of the widget
        chat_log.configure(state='disabled')
        chat_log.yview('end')
#-------------------------------------#
#               SERVER                #
#-------------------------------------#
"""
server(port)
    param: int port
    returns: none
    note: Method used for handling the start up of the server. First the users and passwords
    are loaded from a save file. Then the server start listening for new connections and the admin
    gui is launched.
"""
def server(port):
    global SERVER
    try:
        load()
        SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SERVER.bind( (HOST,int(port)))
        SERVER.listen()
        admin_gui()
    except Exception as e:
        print(e)
    finally:
        save()
        print("Server is turning off.... ")

#-------------------------------------#
#      SERVER Load/Save Methods       #
#-------------------------------------#
"""
save
    note: Method used to save the current users in the user list to the save file.
    First the method checks to see if the KEY and SAVE file exist. Then the save
    file is opened and the contents are loaded into s_file_uNames. The keys of this
    dictionary and the user_list are compared and if there is a difference than
    a new user is found and the saved file is updated. Finally load() is called
    to reinitialize the user_list 
"""
def save():
    try:
        if not os.path.exists(SAVE_FILE) or not os.path.exists(KEY_FILE):
            load()
        s_file_uNames = {}
        with open(SAVE_FILE,'r') as file:
           for line in file:
               uLine = line.split('|')
               s_file_uNames[uLine[0]] = uLine[1]
        new_saves = user_list.keys() - s_file_uNames.keys()
        if len(new_saves) > 0:
            with open(SAVE_FILE,'a') as u_save_file:
                for user in new_saves:
                    en_pass = user_list[user]
                    u_save_file.write(f'{user}|{en_pass}\n')
        load()
        print('Save successful....')
    except Exception as e:
        print(f'Save fail: {e}')
        return False
"""
load
    note: Method used to start up the user_list and populate it with the current known
    users of the server. This is used to check credentials at login. This method
    is called during the start of the server and after any save.

"""
def load():
    try:
        if not os.path.exists(SAVE_FILE) or not os.path.exists(KEY_FILE):
            # !SAVE_FILE
            pass
            if not os.path.exists(KEY_FILE):
                # !KEY_FILE and !SAVE_FILE
                with open(SAVE_FILE,'w') as file:
                    pass
                with open(KEY_FILE,'w') as file:
                    pass
                generate_key()
            else: 
                # !SAVE_FILE but has KEY_FILE
                print('ERROR -> SAVE_FILE NOT PRESENT')
                raise Exception()
        # load the SAVE_FILE
        with open(SAVE_FILE,'r') as s_file:
            for line in s_file:
                entry = line.split('|')
                user_list[entry[0]] = entry[1]
        print('load successful....')
        return True
    except Exception as e:
        print(f'load fail: {e}')
        return False
"""
generate_key
    note: method is used when a new key needs to be generated. This key is 
    used for decoding the encrypted text. The key is a simple
    list of numbers and letters shuffled and saved to the KEY
    file.
"""
def generate_key():
    new_key = list(string.digits + string.ascii_letters)
    random.shuffle(new_key)
    try:
        with open(KEY_FILE,'w') as file:
            for char in new_key:
                file.write(char)
    except Exception as e:
        print(f'Cannot generate key: {e}')
"""
get_key()
    note: method is used to retrieve the key once is is created. It will
    open the KEY file and read the key and return it.

"""
def get_key():
    key = ''
    try:      
        with open(KEY_FILE, 'r') as file:
            key = file.read()
        return key
    except Exception as e:
        print(f'Cannot get key: {e}')

"""
encrypt(msg)
    param: string msg
    return: scrambled and encrypted string
    note: Method will take in a string, get the key
    and then scrambled and encrypt the string.
    It will then return the string
"""
def encrypt(msg):
    key = get_key()
    if key == '':
        load()
    tmp_keys = list(key)
    k_2 = list(string.digits + string.ascii_letters)
    encrypt_msg = ''
    for char in msg:
        index = k_2.index(char)
        encrypt_msg += tmp_keys[index]
    return encrypt_msg
"""
decrypt(msg)
    param: string msg
    return: scrambled and decrypted string
    note: Method will take in a string, get the key
    and then unscrambled and decrypt the string.
    It will then return the string
"""
def decrypt(msg):
    key = get_key()
    if key == '':
        load()
    tmp_keys = list(key)
    k_2 = list(string.digits + string.ascii_letters)
    decrypt_msg = ''
    for char in msg:
        index = tmp_keys.index(char)
        decrypt_msg += k_2[index]
    return decrypt_msg

#-------------------------------------#
#           SERVER Methods            #
#-------------------------------------#
"""
incoming_users(new_client, addr)
    param: client socket, client network address
    return: none
    note: This method is used to handle incoming users. It will first check and see if
    the address is on a banned list of users. This is not implemented in the current
    version of the program but can be added if needed. If the client passes this
    check then the user will be sent to the login screen to get credentials
"""
def incoming_users(new_client, addr):
    try:
        if not EXIT.is_set():
            update_chat_log(f'Client is attempting to join')
            if banned_users.get(addr):
                new_client.send("BANNED".encode('utf-8'))
                new_client.close()
                user = banned_users.get(addr)
                update_chat_log(f"Banned user:{user} attempted to Join")
            else:
                login(new_client)
    except Exception as e:
        print(e)

"""
login(client)
    param: client socket
    return: none
    note: Method will take in a client socket and communicate with them
    until the client sends the correct login credentials or the client
    is a new user. In this case the new user login information is taken in
    and if there is a successful login then a new thread is started and the
    client is connected to the chatroom and can begin sending and receiving
    messages.
"""
def login(client):
    try:
        attempt = 1
        while attempt < 5:
            # 1st recv
            msg = client.recv(1024).decode('utf-8')
            if msg != 'ACK':
                update_chat_log(f'Trouble conncting with user.')
                # 1st send
                client.send("ERR - 1".encode('utf-8'))
                client.close()
                return
            client.send("LOG".encode('utf-8'))
            # 2nd recv
            msg = client.recv(1024).decode('utf-8')
            uName, password = msg.split('|')
            en_uName = encrypt(uName)
            if live_users.get(uName):
                # 2nd send
                client.send("ERR - 2".encode('utf-8'))
                attempt += 1
                continue
            if user_list.get(en_uName):
                user_pass = encrypt(password).strip()
                saved_pass = user_list.get(en_uName).strip()
                if user_pass == saved_pass:
                    # 2nd send
                    client.send('PASS'.encode('utf-8'))
                    handle_thread = threading.Thread(target=handle, args=(client,uName))
                    handle_thread.start()
                    update_chat_log(f'Returning user {uName} has logged in')
                    return
                else:
                    attempt+=1
                    if attempt == 5:
                        client.send("ERR - 3".encode('utf-8'))
                        client.close()
                        return
                    else:
                        client.send("FAIL".encode('utf-8'))
            else:
                #2nd send
                client.send("NEWUSER".encode('utf-8'))
                msg = client.recv(1024).decode('utf-8')
                if msg == "CNL":
                    update_chat_log("Client Cancelled login")
                    client.close()
                    return
                uName, password = msg.split('|')
                new_user(uName,password)
                handle_thread = threading.Thread(target=handle, args=(client,uName))
                handle_thread.start()
                update_chat_log(f'New user {uName} has logged in')
                return
    except Exception as e:
        update_chat_log(f'Login fail: {e}')  
"""
new_user(username, password)
    param: string username
    param: string password
    return: none
    Method is used to take in raw strings encrypted them, add them to the
    user_list and call the save method. This will save the new users to the
    save file.
"""
def new_user(username, password):
    en_uName = encrypt(username)
    en_pass = encrypt(password)
    user_list[en_uName] = en_pass
    save()
"""
def handle(client,uName)
    param: socket client
    param: string uName
    note: Once the user has logged in this will be generated as it own thread.
    This method will communicate with the connect user and will either
    direct their messages or send the user an update of all the active
    users in the server. There are 3 major if statements, each handle
    the users input. 

    Each of these follow the format listed in the assignemnt description.
    The only thing that is different is the error handling on the direct
    message. The user has a updated and constantly updating list of current 
    users, so it is not directly checked in this method. This is checked in
    direct_send().

    1. If header == 'MSG' then the server will handle 
    this as a public message. Error checking on the message is done on 
    the client side.

    2. If header == 'DM' than this method will handle this as a Direct 
    message and will send a message to a specific user. 
    3.Finally if header == 'UPDATE' than the server will ensure connection 
    with the user and send them a list of all current users.

    Since there is a lot going on with the handshaking process each send
    and recv is commented to see how a messages are handled with the user.

"""
def handle(client,uName):
    try:
        live_users[uName] = client
        send_all('ADMIN', f'{uName} has enter the chat...')
        while not EXIT.is_set():
            ## EXPECTED FORMAT
            ## HEADER|<>|RECV|<>|MSG
            #1st recv
            data = client.recv(2048).decode('utf-8').split("|<>|")
            if len(data) != 3:
                ## handle
                return
            if data[0] == 'MSG':
                #1st send
                client.send('ADM|<>|ACK|<>|SENDMSG'.encode('utf-8'))
                #2nd recv
                ret = client.recv(2048).decode('utf-8').split("|<>|")
                if len(ret) == 3 and ret[0] == 'MSG':
                    #2nd send
                    if send_all(uName, ret[2]):
                        #3rd send
                        client.send('ADM|<>|ACK|<>|SEND_TRUE'.encode('utf-8'))
                    else:
                        #3rd send
                        client.send('ADM|<>|ERR|<>|SEND_TRUE'.encode('utf-8'))
            elif data[0] == 'DM':
                ## send ACK
                if live_users.get(data[1]):
                    #1st send
                    client.send('ADM|<>|ACK|<>|SENDMSG'.encode('utf-8'))
                    # 2nd recv
                    ret = client.recv(2048).decode('utf-8').split("|<>|")
                    if len(ret) == 3 and ret[0] == 'DM':
                        # 1st send to another user
                        if direct_send(uName, ret[1], ret[2]):
                            # 2nd send
                            client.send('ADM|<>|ACK|<>|SEND_TRUE'.encode('utf-8'))
                        else:
                            # 2nd send
                            client.send('ADM|<>|ERR|<>|SEND_FALSE'.encode('utf-8'))
            elif data[0] == 'UPDATE':
                envelope = ""
                # 1st send
                client.send(f'ADM|<>|ACK|<>|UPDATE'.encode('utf-8'))
                # 1st recv
                ret = client.recv(2048).decode('utf-8').split("|<>|")
                if len(ret) == 3 and ret[2] == 'READY':
                    for user in live_users.keys():
                        envelope += f'|{user}|'
                    # 2nd send
                    client.send(f'ADM|<>|{envelope}'.encode('utf-8'))   
            elif data[0] == 'EXT':
                # 1st send
                client.send(f'ADM|<>|ACK|<>|EXT'.encode('utf-8'))
                break
            else:
                client.send('ERR - 4'.encode('utf-8'))
    except Exception as e:
        print(e)
    finally:
        leave_msg = f'{uName} has left the chat...'
        live_users.pop(uName)
        send_all("ADMIN", leave_msg)
        client.close()
"""
final_close
    note: method is called when the server is to shutdown. This will set a the 
    EXIT flag. This should notify all and break out of waiting while loops
    the gui is updated as well to ensure that admin cannot save or change the
    server once this is called.
"""
def final_close():
    global save_button, exit_button
    EXIT.set()
    save()
    send_all('ADMIN', "The Server is shuting down...")
    save_button.config(state='disabled')
    exit_button.config(state='disabled')
    send_all('EXIT', 'EXIT')
#-------------------------------------#
#         SERVER Send Methods         #
#-------------------------------------#
"""
send_all(sender, msg)
    param: string sender
    param: string msg
    return: True if the message is sent, False if it fails
    note: Method will take in a message and send it to everyone who is
    currently connected to the server. The message is first formatted
    and it will then look at everyone in live_users and send them a
    message.
"""     
def send_all(sender, msg):
    try:
        envelope = f'MSG|<>|{sender} : {msg}'
        for user in live_users.values():
            ## SENDING MSG
            user.send(envelope.encode('utf-8'))
        if sender != "EXIT" and msg != "EXIT":
            update_chat_log(f'{sender} : {msg}')
        return True
    except:
        return False
"""
direct_send(sender, receiver, msg)
    param: string sender
    param: string receiver
    param: string msg
    return: True if the message is sent, False if it fails
    note: Method will take in a message and send it to only one person. It first
    ensures the person is in the chat. This is also checked on the client side.
    Than the message is formatted and sent to that user only. The admin window
    will see this message as well.
"""   
def direct_send(sender, receiver, msg):
    try:
        if live_users.get(receiver):
            target = live_users.get(receiver)
            sender_sock = live_users.get(sender)
            envelope = f'MSG|<>|{sender} -> {receiver} <PM>: {msg}'
            ## SENDING MSG
            target.send(envelope.encode('utf-8'))
            sender_sock.send(envelope.encode('utf-8'))
            update_chat_log(f'{sender} -> {receiver} <PM>: {msg}')
            return True
        else:
            return False
    except Exception as e:
        return False
#-------------------------------------#
#                main                 #
#-------------------------------------#  
"""
main
    note: This will call the program when the file is located in the command
    prompt and the user calls: python chatserver.py <port#>. If the user does
    not enter a port number or the wrong numebr than the program will not begin  
"""
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('enter a port number and try again')
    else: 
        port = int(sys.argv[1])
        if port > 65535 or port < 1000:
            print('Invalid port, please try again')
        else:
            server(port)

#-------------------------------------#
#             END PROGRAM             #
#######################################
