############ Code Section #############

#######################################
#           Client program            #
#-------------------------------------#

"""
chatclient.py for ChatRoom Project
Author: Paul Siebenaler
Date: 04/09/24
Version: 4.4

"""
#-------------------------------------#
#               imports               #
#-------------------------------------#
import socket
import threading
import tkinter
import tkinter.ttk
import sys
#-------------------------------------#
#          Global Variables           #
#-------------------------------------#
main = tkinter.Tk()
HOST = 'localhost'
EXIT = threading.Event()
CMD_MSG_BELL = threading.Event()
MSG_BELL = threading.Event()
msg_field = ''
chat_msg = ''
Lock = threading.Lock()
VERBOSE = threading.Event()
#-------------------------------------#
#                 GUI                 #
#-------------------------------------#
"""
create_login_window(username)
    param: string name
    note: This is the gui for the first login window. This will start a new window and attach
    itself to the main frame. Then different widgits are added to the frame. The login button will
    initiate the connection with the server. If the password and username are correct the server
    will send a PASS message and the lgoin frame will close and the chatroom frame will open.
    If the server does not reconize the username it will beileve it is a new user. The frame
    will change and allow the user to reenter the password and connect to the server. The gui
    will handle blank and invalid user/password info before it sends it to the server.

    note: For this assignment a gui was not required however I found that features of tkinter 
    widgits could handle the requirements of the assignment better. For example I had a hard time
    an using the command prompt as a text box to type in and receive messages in. I also found it 
    easier to read, test, debug, and use the program with a gui. 
    
    note: if you want to see print() statments, login with a username of 'TEST' 
"""
def create_login_window(username):
    global login_window, uName_login_field, uPass_login_field, attempts 
    global enter_button, exit_button, login_label, CONNECTED, CLIENT
    # commands -----------------------
    CONNECTED = False
    attempts = 1
    CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # frame -----------------------
    login_window = tkinter.Toplevel(main)
    login_window.protocol("WM_DELETE_WINDOW", main.destroy)
    login_window.title("Login Window")
    # widgets creation -----------------------
    login_label =tkinter.Label(login_window, text='ChatRoom Login',font=('Arial', 16))
    uLabel = tkinter.Label(login_window,text="Username:",font=('Arial', 14))
    pLabel = tkinter.Label(login_window,text="Password:",font=('Arial', 14))
    uName_login_field = tkinter.Entry(login_window,font=('Arial', 14), width=20)
    uName_login_field.insert('end', username)
    uPass_login_field = tkinter.Entry(login_window,font=('Arial', 14), show='*', width=20)
    enter_button = tkinter.Button(login_window,text='Enter', font=('Arial', 12), command=attempt_login, padx=5,pady=5)
    exit_button = tkinter.Button(login_window,text='Leave', font=('Arial', 12), command=main.destroy, padx=5,pady=5)
    # layout -----------------------
    login_label.grid(row=0,column=0, columnspan=3, padx=5,pady=5)
    uLabel.grid(row=1,column=0, padx=5, pady=5)
    uName_login_field.grid(row=1,column=1, columnspan=2, padx=5, pady=5)
    pLabel.grid(row=2,column=0, padx=5, pady=5)
    uPass_login_field.grid(row=2,column=1, columnspan=2, padx=5, pady=5)
    exit_button.grid(row=3,column=0,columnspan=2)
    enter_button.grid(row=3,column=2)
"""
update_new_user_GUI()
    note: Fuction will update the current login window to fit another password field. This is so the user
    can reenter the passwords to ensure they entered the correct password at least 2 times. This gui
    will handle the invalid input from the user. If the user fails too many times the connection to the
    sever is severed and the client will return to the first login screen.

"""
def update_new_user_GUI():
    global uPass2_login_field, temp_label, attempts
    # widget state changes -----------------------
    uName_login_field.config(state='disabled')
    exit_button.config(command=return_log, text="Return")
    enter_button.config(command=lambda: new_user(uName_login_field.get().strip(), uPass_login_field.get().strip(), uPass2_login_field.get().strip()))
    uPass_login_field.delete(0,'end')
    login_label.config(text='New user, please check Spelling of username and password')
    # widget creation -----------------------
    temp_label = tkinter.Label(login_window,text="Password:",font=('Arial', 14))
    uPass2_login_field = tkinter.Entry(login_window,font=('Arial', 14), show='*', width=20)
    # layout -----------------------
    login_label.grid(columnspan=4)
    temp_label.grid(row=3,column=0, padx=5, pady=5)
    uPass2_login_field.grid(row=3,column=1, columnspan=2, padx=5, pady=5)
    exit_button.grid(row=4,column=0,columnspan=2)
    enter_button.grid(row=4,column=1,columnspan=2)
"""
return_log()
    note: Function is used to return the user back to the login screen. This will stop the current connetion with server
    and send the server a cancel message. This is used if the user does not want to start as a new user and wants to return
    to the first login screen.

"""
def return_log():
    global CLIENT, CONNECTED
    CLIENT.send("CNL".encode('utf-8'))
    CONNECTED = False
    CLIENT.close()
    login_window.destroy()
    create_login_window('')
"""
create_chat_window
    note: this function is the gui for the chatroom. This will create the window that holds the chat log and the 
    buttons for the user. the widgits are:

    chat_log: This is the chat log. A message handle thread will be listening for all messages from the server. If a
    chat messsage is sent from the server the handler thread will set the chat message so it can be brought to the 
    chat_log and displayed. This process is explained in message_handler()

    leave button: This button acts as the 'EXT' command. This will end the connection. This process is explained in
    leave()

    update_button: This button will send an update request to the server. This process is explained in update_users()

    send_button: This acts as both 'PM' and 'DM' from the assignemnt requiremtns. To send a public message the user
    must have 'ALL' selected in the dropdown box above the send button. If the user wants to send a direct message the
    user must select a user from the dropbox and click send. This explained more in send_message()

    active_users_menu: This is the dropdown box metioned in send_button, contians all the current active users

"""
def create_chat_window():
    global chat_window, chat_log, msg_field, active_users_menu, send_button, leave_button, update_button
    # frame -----------------------
    chat_window = tkinter.Toplevel(main)
    chat_window.title(f"Chat Window: {USER}")
    chat_window.protocol("WM_DELETE_WINDOW", main.destroy)
    # widgets creation -----------------------
    chat_log = tkinter.Text(chat_window,state='disabled',font=('Arial', 16),width = 60, height= 25,wrap=tkinter.WORD,padx=5,pady=5)
    msg_label = tkinter.Label(chat_window,text=">>", font=('Arial', 14))
    msg_field = tkinter.Entry(chat_window,font=('Arial', 16), width=40)
    receiverLabel = tkinter.Label(chat_window,text="TO>", font=('Arial', 14))
    active_users_menu = tkinter.ttk.Combobox(chat_window,width=20,state='readonly', height=10, font=('Arial',14))
    active_users_menu['values'] = "ALL"
    active_users_menu.current(0)
    leave_button = tkinter.Button(chat_window,text="Leave", font=('Arial', 14),command=leave, padx=5, pady=5, width=10)
    update_button = tkinter.Button(chat_window,text="Update Users", font=('Arial', 14),command=update_users, padx=5, pady=5, width=10)
    send_button = tkinter.Button(chat_window,text="Send", font=('Arial', 14),command=send_message, padx=5, pady=5, width=10)
    # layout -----------------------
    chat_log.grid(row=0,column=0,columnspan=7)
    msg_label.grid(row=1,column=0)
    msg_field.grid(row=1,column=1,columnspan=2)
    receiverLabel.grid(row=1,column=3)
    active_users_menu.grid(row=1,column=5)
    leave_button.grid(row=2,column=0,columnspan=2)
    update_button.grid(row=2,column=2)
    send_button.grid(row=2,column=5)
#-------------------------------------#
#            client start             #
#-------------------------------------#
"""
start(user_port, username)
    param: int port, port number used to host server
    param: string username
    note: This function is used to start up the client app and gui. create_login_window()
    will create other threads like the message handler and the chatroom when the user completes
    the login attempt. The notifications are also set to False to ensure they are set properly.
"""
def start(user_port, username):
    global EXIT, CMD_MSG_BELL, port, VERBOSE
    EXIT.clear()
    CMD_MSG_BELL.clear()
    MSG_BELL.clear()
    VERBOSE.clear()
    port = user_port
    create_login_window(username)
    main.withdraw()
    main.mainloop()
    return
#-------------------------------------#
#             client login            #
#-------------------------------------#
"""
attempt_login
    note: This function will handle the user and handle invalid input before
    establishing conneciton to the serer. Also if the user signs in as 'TEST'
    print() statements will be visable.

"""
def attempt_login():
    if uName_login_field.get() == "" or uPass_login_field.get() == "":
        login_label.config(text='Fields cannont be empty')
        return
    if len(uName_login_field.get()) > 20 or len(uPass_login_field.get()) > 20:
        login_label.config(text='username/password is too long')
        uName_login_field.delete(0, 'end')
        uPass_login_field.delete(0, 'end')
        return
    user = uName_login_field.get().strip()
    password = uPass_login_field.get().strip()
    if user == 'TEST':
        VERBOSE.set()
    if str.isalnum(user) and str.isalnum(password):
        login(user,password)
    else: 
        login_label.config(text='username/password can only contain numbers and letters')
        uName_login_field.delete(0, 'end')
        uPass_login_field.delete(0, 'end')
"""
login(uName, password)
    param: string uName
    param: string password
    note: This function will connect to the server and attempt to login. This 
    will first confirm connection and then send the username and password to 
    the server. The server will then send a response to the client after checking
    the credenitals. If the user name is found in the save file and the passwords
    match a new thread which runs the message_handler() is started and the client
    will enter the chatroom. If the user enters the wrong password then they have 
    5 attempts before the server denies the client. Invalid input is handled on the
    client side. If the server does not reconize the username given it will assume
    it is a new user. This will then prompt the user for more info and if the info
    is good then the user will enter the chatroom.

"""    
def login(uName, password):
    global chatroom_thread, uPass2_login_field, CONNECTED
    if not CONNECTED:
        CLIENT.connect( (HOST, port) )
        CONNECTED = True
    try:
        # 1st send
        CLIENT.send('ACK'.encode('utf-8'))
        if VERBOSE.is_set():
            print(f'1st send: ACK')
        # 1st recv
        msg = CLIENT.recv(1024).decode('utf-8')
        if VERBOSE.is_set():
            print(f'1st RECV: {msg}')
        if msg == 'BANNED':
            return
        if msg == 'LOG':
            #2nd send
            CLIENT.send(f'{uName}|{password}'.encode('utf-8'))
            if VERBOSE.is_set():
                print(f'2nd Send: {uName}|{password}')
            #2nd recv
            msg = CLIENT.recv(1024).decode('utf-8')
            if VERBOSE.is_set():
                print(f'2nd RECV: {msg}')
            if msg == 'PASS':
                update_username(uName)
                if VERBOSE.is_set():
                    print(f'Login attempt successful, entering chat...')    
                chatroom_thread = threading.Thread(target=chatroom)
                chatroom_thread.start()
                login_window.destroy()
            elif msg == 'FAIL':
                ## incorrect Password
                login_label.config(text='Wrong Password')
                uPass_login_field.delete(0,'end')
                if VERBOSE.is_set():
                    print(f'Login attempt unsuccessful, wrong password') 
            elif msg == 'NEWUSER':
                update_new_user_GUI()
            elif msg == 'ERR':
                login_label.config(text='Unable to connect with that Username')
                uPass_login_field.delete(0,'end')
                uName_login_field.delete(0,'end')
                if VERBOSE.is_set():
                    print(f'Login attempt unsuccessful') 
            else:
                enter_button.config(state='disabled')
                login_label.config(text='Error, unable to connect')
                uPass_login_field.config(state='disabled')
                uPass2_login_field.config(state='disabled')
                if VERBOSE.is_set():
                    print(f'Login attempt unsuccessful') 
                CONNECTED = False
                CLIENT.close()
    except Exception as e:
        print(e)
"""
new_user(user,password_1,password_2)
    param: string user
    param: string password_1, field 1
    param: string password_2, field 1
    note: Function will take in and handle user input from the 3 entry fields. the user has 5 attempts, after
    this the user will be kicked out of this loop and sent back to the login screen. This will end the connetion
    with the server by calling return_log().
"""
def new_user(user,password_1,password_2):
    global attempts
    if user == "" or password_1 == "" or password_2 == "":
        login_label.config(text="Fields cannot be blank")
        uPass_login_field.delete(0,'end')
        uPass2_login_field.delete(0,'end')
        attempts += 1

    elif len(user) > 20 or len(password_1) > 20 or len(password_2) > 20:
        login_label.config(text="Password/Username is too long")
        uPass_login_field.delete(0,'end')
        uPass2_login_field.delete(0,'end')
        attempts += 1

    elif password_1 != password_2:
        login_label.config(text="Passwords do not match")
        uPass_login_field.delete(0,'end')
        uPass2_login_field.delete(0,'end')
        attempts += 1

    elif user == '|<>|':
        login_label.config(text="cannot use username, illegal sysmbol: |<>|")
        uPass_login_field.delete(0,'end')
        uPass2_login_field.delete(0,'end')
        attempts += 1
    elif not str.isalnum(password_1)  or not str.isalnum(password_2):
        login_label.config(text="Passwords can only be numebr and letters")
        uPass_login_field.delete(0,'end')
        uPass2_login_field.delete(0,'end')
        attempts += 1

    else:
        envelope = f'{user}|{password_1}'
        CLIENT.send(envelope.encode('utf-8'))
        update_username(user)
        if VERBOSE.is_set():
           print(f'Login attempt successful, entering chat...')
        chatroom_thread = threading.Thread(target=chatroom)
        chatroom_thread.start()
        login_window.destroy()

    if attempts == 5:
        attempts = 0
        login_label.config(text=f'Returning to login screen....')
        enter_button.config(state='disabled')
        exit_button.config(state='disabled')
        login_window.after(5000, return_log)
"""
update_username(name)
    param: string name
    note: This is only used to set the title on the main chatroom frame
"""
def update_username(name):
    global USER
    USER = name    
#-------------------------------------#
#               Chatroom              #
#-------------------------------------#
"""
chatroom
    note: Once the user is passes the login check this fuction is called to create
    the chatroom gui. Also the chat_log thread and the message handler thread are created
    and started. 
"""
def chatroom():
    create_chat_window()
    chat_log_thread = threading.Thread(target=print_chat)
    chat_log_thread.start()
    msg_handler_thread = threading.Thread(target=message_handler)
    msg_handler_thread.start()
    update_users()

#-------------------------------------#
#      Chatroom message handling      #
#-------------------------------------#
"""
print_chat
    note: This function is designed to respond to a change of the MSG_BELL.
    This function is designed to be it own thread and to wait untill the
    MSG_BELL is set. It is set only when the message handler receives a
    chat message from the server. When the bell is rung this will wake up,
    get the message and post this message to the chat_log for the user. When
    the fucntion get_chat_msg() is called this will reset the MSG_BELL. 
    After this the thread will wait until the MSG_BELL is set again.
"""    
def print_chat():
    while not MSG_BELL.is_set() and not EXIT.is_set():
        MSG_BELL.wait()
        msg = get_chat_msg()
        if VERBOSE.is_set():
            print(f'incoming chat MSG: {msg}\n') 
        if msg != '':
            chat_log.configure(state='normal')  # Set state to normal to allow editing
            chat_log.insert('end', msg + '\n')  # Insert text at the end of the widget
            chat_log.configure(state='disabled')
            chat_log.yview('end')
"""
message_handler
    note: This function works as a switch for incoming message. When a new message is
    received from the user is will look at the header of the message and notify the
    the correct receiver of this message. If the header is 'MSG' then the message handler
    will call the function set_chat_message(). This will handoff this msg and the waiting
    print_chat thread will wake and print this message to the chat long. If the header is
    'ADM', than the message is a command message. The handler will call the function
    set_cmd_msg. This will notify threads waiting on a command message.
"""
def message_handler():
    try:
        MSG_BELL.clear()
        while not EXIT.is_set():
            raw_msg = CLIENT.recv(1024).decode('utf-8')
            if VERBOSE.is_set():
                print(f'Recv MSG from server: {raw_msg}')
            msg = raw_msg.split('|<>|')
            if msg[0] == 'MSG':
               if msg[1] == 'EXIT : EXIT':
                   send_button.config(state='disabled')
                   update_button.config(state='disabled')
                   leave_button.config(state='disabled')
                   CLIENT.close()
                   return
               set_chat_msg(msg[1])
            elif msg[0] == 'ADM':
                set_CMD_MSG(msg)
            else:
                continue
    except Exception as e:
        EXIT.set()
"""
set_CMD_MSG(msg)
    param: string msg
    note: this function is called when the handler recieces a command message. The
    message is saved as a variable to get grabbed by a different thread once that
    wake up.
"""
def set_CMD_MSG(msg):
    global CMD_MSG
    if VERBOSE.is_set():
        print(f'Setting Command MSG and notifying....')
    Lock.acquire()
    CMD_MSG = msg
    Lock.release()
    CMD_MSG_BELL.set()
"""
get_CMD_MSG
    note: This function is used to get the command message that the message handler set. Many
    different functions will call this to get the command message to continue with their
    task.
"""
def get_CMD_MSG():
    global CMD_MSG
    msg = CMD_MSG
    CMD_MSG = ''
    CMD_MSG_BELL.clear()
    return msg
"""
set_chat_msg(msg)
    param: string msg
    note: this function is called when the handler recieces a chat message. The
    message is saved as a variable to get grabbed by a different thread once they
    wake up.
"""
def set_chat_msg(msg):
    global chat_msg
    if VERBOSE.is_set():
        print(f'Setting Chat MSG and notifying....')
    Lock.acquire()
    chat_msg = msg
    Lock.release()
    MSG_BELL.set()
"""
get_chat_msg
    note: This function is used to get the chat message that the message handler set. print_chat() 
    will call this to get the chat message and print it to the chat_log
"""
def get_chat_msg():
    global chat_msg
    msg = chat_msg
    chat_msg = ''
    MSG_BELL.clear()
    return msg

#-------------------------------------#
#        chatroom user methods        #
#-------------------------------------#
"""
send_message
    note: This is a button on the chatroom window. When this button is clicked the information
    will be sent and evaluated by the server. There are two kinds of messages, direct and private.
    The functiuon will look at who the reiecer is and determine if it is a direct message. If the
    reciever is 'ALL' than a public message is send. If it is a user than a direct message is sent.
    With each message there is certain handshaking with the server. This will send a message to the
    server and then wait on the response. Once the message handler recieves a commadn message this
    will wake and contuine with the send message function.

"""
## send button
def send_message():
    update_users()
    msg = msg_field.get()
    if len(msg) > 250:
        set_chat_msg(">> Message too Long. Not Sent")
        set_chat_msg(f">> Max Message length is 250. Your message is {len(msg)} long.")
        return
    elif msg == '':
        set_chat_msg(">> Message Field Blank")
        return
    if '|<>|' in msg:
        set_chat_msg(">> Unable to send, illegal symbol: |<>| ")
        return
    receiver = active_users_menu.get()
    if receiver == 'ALL':
        header = 'MSG'
        ## SEND ALL
        #1st send
        if VERBOSE.is_set():
            print(f'\nSending public message....')
        envelope = f'{header}|<>|ADM|<>|ACK'
        CLIENT.send(envelope.encode('utf-8'))
        if VERBOSE.is_set():
            print(f'#1st send: {envelope}')
        while not CMD_MSG_BELL.is_set() and not EXIT.is_set():
            CMD_MSG_BELL.wait()
        #1st recv
        ret_1 = get_CMD_MSG()
        if len(ret_1) == 3 or ret_1[1] == 'ACK':
            #2nd send
            envelope = f'{header}|<>|{receiver}|<>|{msg}'
            CLIENT.send(envelope.encode('utf-8'))
            if VERBOSE.is_set():
                print(f'#2nd send: {envelope}')
            while not CMD_MSG_BELL.is_set() and not EXIT.is_set():
                CMD_MSG_BELL.wait()
                # 2nd recv handled by other thread
            # 3rd recv
            ret_2 = get_CMD_MSG()
            if len(ret_2) != 3 or ret_2[1] == 'ERR':
                set_chat_msg(f'ADM: MESSAGE NOT SENT')
                return
    else:
        header = 'DM'
        ## Direct Message
        if VERBOSE.is_set():
            print('\nSending a private message......')
        if receiver in active_users_menu['values']:
            #1st send
            envelope = f'{header}|<>|{receiver}|<>|ACK'
            CLIENT.send(envelope.encode('utf-8'))
            if VERBOSE.is_set():
                print(f'#1st send: {envelope}')
            while not CMD_MSG_BELL.is_set() and not EXIT.is_set():
                CMD_MSG_BELL.wait()
            #1st recv    
            ret_1 = get_CMD_MSG()
            if len(ret_1) == 3 and ret_1[1] == 'ACK':
                # 2nd send
                envelope = f'{header}|<>|{receiver}|<>|{msg}'
                CLIENT.send(envelope.encode('utf-8'))
                if VERBOSE.is_set():
                    print(f'2nd send: {envelope}')
                while not CMD_MSG_BELL.is_set() and not EXIT.is_set():
                    CMD_MSG_BELL.wait()
                #2nd recv
                ret_2 = get_CMD_MSG()
                if len(ret_2) != 3 or ret_2[1] == 'ERR':
                    set_chat_msg(f'ADM: MESSAGE NOT SENT')         
    msg_field.delete(0,'end')
"""
update_users
    note: This function is used to get a current list of active users connected to the
    server. The results of this will update the active_users_menu. From there the user
    can send messages to direct users. The current user is removed from the update list
    so the user cannot send a private message to themselves.
"""
## update button
def update_users():
    #1st send
    if VERBOSE.is_set():
        print(f'\nUpdating the active users list....')
    envelope = f'UPDATE|<>|ADMIN|<>|GET_USER_UPDATE'
    CLIENT.send(envelope.encode('utf-8'))
    if VERBOSE.is_set():
        print(f'1st send: {envelope}')
    while not CMD_MSG_BELL.is_set() and not EXIT.is_set():
        CMD_MSG_BELL.wait()
    # 1st recv
    ret = get_CMD_MSG()
    if len(ret) == 3 and ret[1] == 'ACK':
        #2nd send
        CLIENT.send('UPDATE|<>|ADM|<>|READY'.encode('utf-8'))
        if VERBOSE.is_set():
            print(f'2nd send: {envelope}')
        while not CMD_MSG_BELL.is_set() and not EXIT.is_set():
            CMD_MSG_BELL.wait()
        # 2nd recv
        ret = get_CMD_MSG()
        current_users = ret[1].split("|")
        filtered_list = list(filter(None, current_users))
        filtered_list.append('ALL')
        if USER in filtered_list:
            filtered_list.remove(USER)
    active_users_menu['values'] = filtered_list
"""
leave
    note: This function will send a message to the server stating that it want to leave. The
    server will send an ack message and both sides will disconnect. the server will then notify
    all the connected users that a person has left. This function will also disable the buttons
    so the user cannont sent anymore messages or get the list of connected users.
"""
## Leave button
def leave():
    global CONNECTED
    try:
        update_button.config(state='disabled')
        send_button.config(state='disabled')
        leave_button.config(text="Exit",command=main.destroy)
        msg_field.config(state='readonly')
        # 1st send
        envelope = f'EXT|<>|NONE|<>|ADMIN'
        CLIENT.send(envelope.encode('utf-8'))
        if VERBOSE.is_set():
            print(f'1st send: {envelope}')
        while not CMD_MSG_BELL.is_set() and not EXIT.is_set():
            CMD_MSG_BELL.wait()
        #1st recv
        ret = get_CMD_MSG()
        if len(ret) == 3 and ret[1] == 'ACK':
            set_chat_msg("Logged out...")
        else:
            set_chat_msg("Error Logging out...")
    except Exception as e:
        print(f'Leave Error: {e}')
    finally:
        CONNECTED = False
        CLIENT.close()
        EXIT.set()
        if VERBOSE.is_set():
            print(f'Exiting chat....')

#-------------------------------------#
#                main                 #
#-------------------------------------#

"""
main
    note: This will call the program when the file is located in the command
    prompt and the user calls: python chatclient.py <port#> <username>. If the user does
    not enter a port number or an invalid number than the program will not begin. This is
    also true for the username.  
"""
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('enter a port number and try again')
    else: 
        port = int(sys.argv[1])
        username = str(sys.argv[2])
        if port > 65535 or port < 1000:
            print('Invalid port, please try again')
        elif len(username) > 50 or len(username) < 0:
            print('Invalid username, please try again')
        else: 
            start(port, username)