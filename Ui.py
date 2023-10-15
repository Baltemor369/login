import tkinter as tk
import tkinter.ttk as ttk
import re
from Login import Login
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

class Ui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Login")
        self.config(bg=BG)
        self.login = Login(("root","root"))
        self.current_page = None

    def run(self):
        self.display_login()
        self.mainloop()
    
    def display_login(self):
        clear(self)

        self.bind("<Return>", self.login_verification)
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

        self.current_page = "login"

        frame = tk.Frame(self, **FRAME)
        frame.pack(anchor="center")
        
        L_user = tk.Label(frame, text="User : ", **LABEL)
        L_user.pack()

        self.E_user = tk.Entry(frame, **ENTRY)
        self.E_user.pack()
        self.E_user.focus_set()

        L_password = tk.Label(frame, text="Password : ", **LABEL)
        L_password.pack()

        self.E_password = tk.Entry(frame, show="♥", **ENTRY)
        self.E_password.pack()

        self.B_show_password = tk.Button(frame, text="Show", command=self.toggle_visibility, **BUTTON7)
        self.B_show_password.pack()

        B_connection = tk.Button(frame, text="Connect", command=self.login_verification, **BUTTON7)
        B_connection.pack(pady=15)

        set_geometry(self)
    
    def login_verification(self, e=None):
        username = self.E_user.get()
        pasword = self.E_password.get()

        # TODO check entry

        if self.login.check_login(username, pasword) >= 0:
            # login success as a admin            
            self.state('zoomed')
            self.display_admin()

    def display_admin(self):
        clear(self)

        Left_Frame = tk.Frame(self, **FRAME)
        Right_Frame = tk.Frame(self, **FRAME)
        Bot_Frame = tk.Frame(self, **FRAME)
        Left_Frame.pack()
        Right_Frame.pack()
        Bot_Frame.pack()

        tk.Button(Bot_Frame, text="Add User", command=self.display_add_user, **BUTTON10).pack()
        tk.Button(Bot_Frame, text="Disconnect", command=self.disconnection, **BUTTON10).pack()

        self.display_users(Left_Frame)
        self.display_logs(Right_Frame)

    def display_users(self, frame:tk.Tk|tk.Frame):
        for elt in self.login.get_users():
            tk.Label(frame, text=f"{elt[0]}, {elt[1]}", **LABEL).pack()

    def display_logs(self, frame:tk.Frame|tk.Tk):
        for elt in self.login.get_logs(10):
            tk.Label(frame, text=elt, **LABEL).pack()            

    def display_add_user(self):
        
        self.window = tk.Toplevel(self)
        self.window.attributes("-topmost",1)
        self.window.title("Add User")
        self.window.config(bg=BG)
        
        self.window.bind("<Return>", self.confirm)
        # label name
        tk.Label(self.window, text="Username", **LABEL).grid(row=0,column=0)
        # entry name
        self.E_name = tk.Entry(self.window, **ENTRY)
        self.E_name.grid(row=0,column=1)
        self.E_name.focus_set()
        # label password
        tk.Label(self.window, text="Password", **LABEL).grid(row=1,column=0)
        # entry password
        self.E_password = tk.Entry(self.window, show="♥", **ENTRY)
        self.E_password.grid(row=1,column=1)

        # label confirm password
        tk.Label(self.window, text="Confirm Password", **LABEL).grid(row=2,column=0)
        # entry confirm password
        self.E_c_password = tk.Entry(self.window, show="♥", **ENTRY)
        self.E_c_password.grid(row=2,column=1)

        # label status
        tk.Label(self.window, text="Status", **LABEL).grid(row=3,column=0)
        # entry status
        self.E_status = tk.Entry(self.window, **ENTRY)
        self.E_status.grid(row=3,column=1)

        # button confirm
        tk.Button(self.window, text="Confirm", command=self.confirm, **BUTTON7).grid(row=4,column=0,columnspan=2)
        
        # button disconnect
        tk.Button(self.window, text="Cancel", command=self.window.destroy, **BUTTON7).grid(row=5,column=0,columnspan=2)

        self.wait_window(self.window)
        
    def confirm(self):
        name = self.E_name.get()
        password = self.E_password.get()
        c_password = self.E_c_password.get()
        status = self.E_status.get()

        # TODO : check entry

        if password == c_password:
            self.login.add_user(name,password,status)
            self.window.destroy()
            self.display_admin()
    
    def toggle_visibility(self):
        current_show = self.E_password.cget("show")
        if current_show:
            self.E_password.configure(show="")
        else:
            self.E_password.configure(show="♥")
    
    def disconnection(self):
        self.login.disconnect()
        self.display_login()
    
    def on_exit(self):
        if self.login.user:
            self.login.disconnect()
        self.destroy()