import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import sqlite3 as sql
import bcrypt as crypt

from const import *

def set_geometry(self:tk.Tk|tk.Toplevel, margin_EW:int=100, margin_NS:int=20, center:bool=True):
    self.update_idletasks()
    width = self.winfo_reqwidth() + margin_EW  # margin E-W
    height = self.winfo_reqheight() + margin_NS  # margin N-S

    x = (self.winfo_screenwidth() // 2) - (width // 2)
    y = (self.winfo_screenheight() // 2) - (height // 2)
    if center:
        self.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    else:
        self.geometry('{}x{}'.format(width, height))

def clear(self:tk.Tk|tk.Frame):
    for widget in self.winfo_children():
            widget.destroy()

class Login(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Login")
        
        self.bind('<Return>', self.bind_return_key)
        self.bind('<Escape>', self.on_exit)
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

        # init user database
        database = sql.connect(DB_USER)
        cursor = database.cursor()
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS users (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       username TEXT NOT NULL,
                       password TEXT NOT NULL,
                       status int
                       )
                       ''')
        database.commit()        
        database.close()

        # init log database
        database = sql.connect(DB_LOG)
        cursor = database.cursor()
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS logs (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       log TEXT
                       )
                       ''')
        database.commit()        
        database.close()

        self.salt = crypt.gensalt()

        # add default admin
        name = "admin"
        pw = crypt.hashpw("admin".encode("utf-8"), self.salt)
        if len(self.request_user("SELECT * FROM users WHERE username=?", (name, )))==0:
            self.request_user("INSERT INTO users (username, password, status) VALUES (?, ?, ?)",(name, pw, 1))

        self.cookie = {
            "user":"",
            "status":-1,
        }

        self.display_login()

    def run(self):
        self.mainloop()
    
    def on_exit(self, evt=None):
        if self.cookie['user']:
            self.disconnect()

        self.destroy()

    ### DISPLAY FUNCTIONS ###

    def display_login(self):
        clear(self)

        self.current_page = "login"

        frame = tk.Frame(self)
        frame.pack(anchor="center")
        
        L_user = tk.Label(frame, text="User : ")
        L_user.pack()

        self.E_user = tk.Entry(frame)
        self.E_user.pack()

        L_password = tk.Label(frame, text="Password : ")
        L_password.pack()

        self.E_password = tk.Entry(frame, show="*")
        self.E_password.pack()

        self.B_show_password = tk.Button(frame, text="Show", command=self.toggle_password_visibility)
        self.B_show_password.pack()

        B_connection = tk.Button(frame, text="Connect", command=self.login)
        B_connection.pack()

        set_geometry(self)
    
    def toggle_password_visibility(self):
        current_show = self.E_password["show"]
        if current_show:
            self.E_password["show"] = ""
            self.B_show_password.config(text="Hide")
        else:
            self.E_password["show"] = "*"
            self.B_show_password.config(text="Show")

    def display_logged(self):
        clear(self)

        self.current_page = "logged"

        tk.Label(self, text=f"{self.cookie['user']} Connected !").pack()
        
        if self.cookie["status"]>0:
            B_add_user = tk.Button(self, text="add", command=self.display_add_user)
            B_add_user.pack()

            B_del_user = tk.Button(self, text="delete", command=self.display_delete_user)
            B_del_user.pack()

            B_del_user = tk.Button(self, text="show logs", command=self.display_logs)
            B_del_user.pack()
        
        B_disconnection = tk.Button(self, text="Disonnect", command=self.toggle_disconnect)
        B_disconnection.pack()
        
        set_geometry(self)
    
    def display_logs(self):
        clear(self)

        self.current_page = "logs"

        logs = self.get_logs()
        
        for line in logs:
            tk.Label(self, text=line).pack()
        
        tk.Button(self, text="Back", command=self.display_logged).pack()

        set_geometry(self)
    
    def display_add_user(self):
        clear(self)

        self.current_page = "add"

        frame = tk.Frame(self)
        frame.pack(anchor="center")
        
        L_user = tk.Label(frame, text="User : ")
        L_user.pack()

        self.E_user = tk.Entry(frame)
        self.E_user.pack()

        L_password = tk.Label(frame, text="Password : ")
        L_password.pack()

        self.E_password = tk.Entry(frame, show="*")
        self.E_password.pack()

        self.B_show_password = tk.Button(frame, text="Show", command=self.toggle_password_visibility)
        self.B_show_password.pack()

        L_status = tk.Label(frame, text="Status : ")
        L_status.pack()

        self.E_status = tk.Entry(frame)
        self.E_status.pack()

        B_connection = tk.Button(frame, text="Add", command=self.signup)
        B_connection.pack()

        set_geometry(self)
    
    def display_delete_user(self):
        clear(self)

        self.current_page = "delete"

        # Create a delete user button and entry field for the admin
        delete_username_label = tk.Label(self, text="Enter username to delete:")
        delete_username_label.pack()
        
        self.E_username = tk.Entry(self)
        self.E_username.pack()

        delete_button = tk.Button(self, text="Delete User", command=self.del_user)
        delete_button.pack()
    
    ### BACK FUNCTIONs ###
    
    def login(self):
        user = self.E_user.get()
        password = self.E_password.get()

        # TODO check entry char
        
        # Retrieve the hashed password from the database
        result = self.request_user("SELECT username,password,status FROM users WHERE username=?", (user,))

        if len(result)>1:
            print(result)
            messagebox.showerror("Login Failed","More than one user found.")
        elif len(result)==1:
            elt = result[0]
            if crypt.checkpw(password.encode('utf-8'), elt[1]):
                self.cookie["user"] = elt[0]
                self.cookie["status"] = elt[2]                
                
                # Get the current date and time
                current_datetime = datetime.now()
                formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
                self.add_log(f"{self.cookie['user']} connected at {formatted_datetime}")
                
                self.display_logged()
        elif len(result)==0:
            messagebox.showerror("Login Failed","Invalid user or password.")
        else:
            messagebox.showerror("Login Failed","Return values < 0.")
    
    def signup(self):
        user = self.E_user.get()
        password = self.E_password.get()
        status = int(self.E_status.get())

        self.add_user(user, password, status)

        # Get the current date and time
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
        self.add_log(f"{self.cookie['user']} add user {user} at {formatted_datetime}")
        self.display_logged()

    def add_user(self, name:str, password:str, status:int):
        
        # TODO check values
        
        # Hash the plaintext password using bcrypt
        hashed_password = crypt.hashpw(password.encode('utf-8'), self.salt)

        self.request_user("INSERT INTO users (username, password, status) VALUES (?, ?, ?)",(name, hashed_password, status))

    def del_user(self):
        username = self.E_username.get()

        # TODO check values

        result = self.request_user("SELECT id FROM users WHERE username=?", (username,))
        if len(result)==1:
            self.request_user("DELETE FROM users WHERE id=?", (result[0]))
            messagebox.showinfo("User delete", f"User {username} has been deleted.")

            # Get the current date and time
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
            self.add_log(f"{self.cookie['user']} delete user {username} at {formatted_datetime}")
            
            self.display_logged()
    
    def toggle_disconnect(self):
        self.disconnect()
        self.display_login()


    def disconnect(self):
        # Get the current date and time
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")

        self.add_log(f"{self.cookie['user']} disconnected at {formatted_datetime}")

        self.cookie['user'] = ""
        self.cookie['status'] = -1
    
    def request_user(self, cmd:str, values:tuple|list):
        database = sql.connect(DB_USER)
        cursor = database.cursor()
        
        cursor.execute(cmd, tuple(values))
        
        result = cursor.fetchall()
        
        database.commit()
        database.close()
        
        return result
    
    def request_log(self, cmd:str, values:tuple|list):
        database = sql.connect(DB_LOG)
        cursor = database.cursor()
        
        cursor.execute(cmd, tuple(values))
        
        result = cursor.fetchall()
        
        database.commit()
        database.close()
        
        return result

    def bind_return_key(self, event):
        if self.current_page == "login":
            self.login()
        elif self.current_page == "add":
            self.signup()
        elif self.current_page == "delete":
            self.del_user()
    
    def add_log(self, text:str):
        database = sql.connect(DB_LOG)
        cursor = database.cursor()
        
        cursor.execute("INSERT INTO logs (log) VALUES (?)", (text,))
        
        database.commit()
        database.close()
    
    def get_logs(self):
        database = sql.connect(DB_LOG)
        cursor = database.cursor()
        
        result = cursor.execute("SELECT log FROM logs ORDER BY id DESC LIMIT 10")
        result = result.fetchall()

        database.commit()
        database.close()

        return result