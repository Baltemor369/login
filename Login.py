from datetime import datetime
import sqlite3 as sql
import bcrypt as crypt

from const import *

class Login():
    def __init__(self, default_admin:tuple[str,str]=None) -> None:
        self.cookie = {
            "user":"",
            "status":-1,
        }
        self.user = False
        self.init_database(default_admin)

    def init_database(self, default_admin:tuple[str,str]=None):
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

        # add default admin
        if default_admin:
            name = default_admin[0]
            pw = crypt.hashpw(default_admin[1].encode("utf-8"), crypt.gensalt())
            if len(self.request_user_DB("SELECT * FROM users WHERE username=?", (name, )))==0:
                self.request_user_DB("INSERT INTO users (username, password, status) VALUES (?, ?, ?)",(name, pw, 1))
   
    def check_login(self, username:str, password:str) -> int:
        # Retrieve the hashed password from the database
        result = self.request_user_DB("SELECT username,password,status FROM users WHERE username=?", (username,))

        if len(result)>1:
            return -1 # too much user register with this name, registering process issue
        
        elif len(result)==1:
            elt = result[0]
        
            if crypt.checkpw(password.encode('utf-8'), elt[1]):
                self.cookie["user"] = elt[0]
                self.cookie["status"] = elt[2]
                self.user = True
                
                # Get the current date and time
                current_datetime = datetime.now()
                formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
                self.add_log(f"{self.cookie['user']} connected at {formatted_datetime}")
                return self.cookie["status"]
            
        elif len(result)==0:
            return -2 # no user register with this name
        
        else:
            return -3 # unexpected return
    
    def new_user(self, username:str, password:str, status:int) -> bool:
        if self.add_user(username, password, status):
            # Get the current date and time
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
            self.add_log(f"{self.cookie['user']} add user {username} at {formatted_datetime}")

    def add_user(self, username:str, password:str, status:int) -> bool:
        result = self.request_user_DB("SELECT id FROM users WHERE username=?", (username,))
        if len(result) == 0:
            # Hash the plaintext password using bcrypt
            hashed_password = crypt.hashpw(password.encode('utf-8'), crypt.gensalt())
            self.request_user_DB("INSERT INTO users (username, password, status) VALUES (?, ?, ?)",(username, hashed_password, status))
            return True
        return False

    def delete_user(self, username:str) -> bool:
        result = self.request_user_DB("SELECT id FROM users WHERE username=?", (username,))

        if len(result)==1:
            self.request_user_DB("DELETE FROM users WHERE id=?", (result[0],))

            # Get the current date and time
            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
            self.add_log(f"{self.cookie['user']} delete user {username} at {formatted_datetime}")
            return True
        return False

    def disconnect(self):
        # Get the current date and time
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%d/%m/%Y %H:%M:%S")
        self.add_log(f"{self.cookie['user']} disconnected at {formatted_datetime}")
        self.cookie['user'] = ""
        self.cookie['status'] = -1
        self.user = False
    
    def request_user_DB(self, cmd:str, values:tuple|list):
        database = sql.connect(DB_USER)
        cursor = database.cursor()
        cursor.execute(cmd, tuple(values))
        result = cursor.fetchall()
        database.commit()
        database.close()
        return result
    
    def request_log_DB(self, cmd:str, values:tuple|list):
        database = sql.connect(DB_LOG)
        cursor = database.cursor()
        cursor.execute(cmd, tuple(values))
        result = cursor.fetchall()
        database.commit()
        database.close()
        return result
    
    def add_log(self, text:str):
        database = sql.connect(DB_LOG)
        cursor = database.cursor()
        
        cursor.execute("INSERT INTO logs (log) VALUES (?)", (text,))
        
        database.commit()
        database.close()
    
    def get_logs(self, limit:int):
        database = sql.connect(DB_LOG)
        cursor = database.cursor()
        
        result = cursor.execute("SELECT log FROM logs ORDER BY id DESC LIMIT ?",(limit,))
        result = result.fetchall()

        database.commit()
        database.close()

        return result

    def get_name(self):
        return self.cookie["user"]
    
    def get_status(self):
        return self.cookie["status"]
    
    def get_users(self):
        cmd = "SELECT username,status FROM users"
        return self.request_user_DB(cmd,())