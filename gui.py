import DNSLookup as dns
import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as msgbox


class ExtraInfo(tk.Toplevel):

    def show(self, name, info):
        height = max(max(len(info.get("ipv4")), len(info.get("ipv6"))), 1) * 20 + 120
        width = 600
        cent_x = self.winfo_screenwidth()//2 - width//2
        cent_y = self.winfo_screenheight()//2 - height//2
        self.wm_geometry(f"{width}x{height}+{cent_x}+{cent_y}")
        self.title(name)

        frame = ttk.Frame(self)
        labels = ttk.Frame(frame)
        tables = ttk.Frame(frame)

        tabv4 = ttk.Treeview(tables, height=max(len(info.get("ipv4")), 1))
        tabv4.heading("#0", text='IPv4 Adresses', anchor=tk.W)
        tabv4.column('#0', anchor=tk.W, stretch=True, minwidth=150)

        tabv6 = ttk.Treeview(tables, height=max(len(info.get("ipv6")), 1))
        tabv6.heading("#0", text='IPv6 Adresses', anchor=tk.W)
        tabv6.column('#0', anchor=tk.W, stretch=True, minwidth=300)

        if info.get("cname") is None:
            ttk.Label(labels, text="Host name: " + name, font=(None, 14)).pack(side=tk.TOP, anchor=tk.W,
                                                                               padx=10, pady=2)
            for addr in info.get('ipv4'):
                tabv4.insert('', 'end', text=addr)
            for addr in info.get('ipv6'):
                tabv6.insert('', 'end', text=addr)
            if len(info.get('ipv4')) == 0:
                tabv4.insert('', 'end', text='None')
            if len(info.get('ipv6')) == 0:
                print("0")
                tabv6.insert('', 'end', text='None')

        else:
            ttk.Label(labels, text="Alias: " + name, font=(None, 14)).pack(side=tk.TOP, anchor=tk.W, padx=10, pady=2)
            ttk.Label(labels, text="Canonical Name: " + name, font=(None, 14)).pack(side=tk.TOP, anchor=tk.W,
                                                                                    padx=10, pady=2)
            tabv4.insert('', 'end', text='N/A')
            tabv6.insert('', 'end', text='N/A')

        tabv4.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=False)
        tabv6.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)

        labels.pack(side=tk.TOP, fill=tk.X, expand=True)
        tables.pack(side=tk.TOP, fill=tk.X, expand=True)

        frame.pack(fill=tk.BOTH, expand=True)


class IPTable(ttk.Treeview):

    def show(self, ip, info):
        self['columns'] = ('col',)
        self.heading('#0', text='    IP Address', anchor=tk.W)
        self.column('#0', anchor=tk.W, stretch=True, minwidth=150)
        self.heading('col', text='Host name', anchor=tk.W)
        self.column('col', anchor=tk.W, stretch=True, minwidth=150)

        self.insert('', 'end', text=ip, values=(", ".join(info),))


class HostTable(ttk.Treeview):

    def show(self, info):
        self._info = info

        self['columns'] = ('cname', 'ipv4', 'ipv6')
        self.heading('#0', text='    Host Name', anchor=tk.W)
        self.column('#0', anchor=tk.W, stretch=True, minwidth=175)
        self.heading('cname', anchor=tk.W, text='Canonical Name')
        self.column('cname', anchor=tk.W, stretch=True, minwidth=175)
        self.heading('ipv4', anchor=tk.W, text='IPv4 Address')
        self.column('ipv4', anchor=tk.W, stretch=True, minwidth=150)
        self.heading('ipv6', anchor=tk.W, text='IPv6 Address')
        self.column('ipv6', anchor=tk.W, stretch=True, minwidth=300)

        for name in info:
            host_info = info[name]
            if len(host_info.get('ipv4')) == 0:
                ipv4 = "None"
            elif len(host_info.get('ipv4')) > 1:
                ipv4 = "(double-click to view)"
            else:
                ipv4 = host_info['ipv4'][0]
            if len(host_info.get('ipv6')) == 0:
                ipv6 = "None"
            elif len(host_info.get('ipv6')) > 1:
                ipv6 = "(double-click to view)"
            else:
                ipv6 = host_info['ipv6'][0]
            if host_info.get('cname') is not None:
                ipv4 = "N/A"
                ipv6 = "N/A"
                cname = host_info['cname']
            else:
                cname = "None"
            self.insert('', 'end', text=name, values=(cname, ipv4, ipv6))

        self.bind("<Double-1>", self.on_click)

    def on_click(self, event):
        print("click")
        item = self.selection()[0]
        name = self.item(item, "text")
        ExtraInfo(self).show(name, self._info[name])


class MailTable(ttk.Treeview):

    def show(self, info):
        self._info = info

        self['columns'] = ('ipv4', 'ipv6')
        self.heading('#0', text='    Host Name', anchor=tk.W)
        self.column('#0', anchor=tk.W, stretch=True, minwidth=350)
        self.heading('ipv4', anchor=tk.W, text='IPv4 Address')
        self.column('ipv4', anchor=tk.W, stretch=True, minwidth=150)
        self.heading('ipv6', anchor=tk.W, text='IPv6 Address')
        self.column('ipv6', anchor=tk.W, stretch=True, minwidth=300)

        for m in info:
            mail_info = info[m]
            if len(mail_info.get('ipv4')) == 0:
                ipv4 = "None"
            elif len(mail_info.get('ipv4')) > 1:
                ipv4 = "(double-click to view)"
            else:
                ipv4 = mail_info['ipv4'][0]
            if len(mail_info.get('ipv6')) == 0:
                ipv6 = "None"
            elif len(mail_info.get('ipv6')) > 1:
                ipv6 = "(double-click to view)"
            else:
                ipv6 = ",\n".join(mail_info['ipv6'])
            self.insert('', 'end', text=m, values=(ipv4, ipv6))

        self.bind("<Double-1>", self.on_click)

    def on_click(self, event):
        print("click")
        item = self.selection()[0]
        name = self.item(item, "text")
        ExtraInfo(self).show(name, self._info[name])


class IPInfo(ttk.LabelFrame):

    def fill(self, ip, info):
        i = IPTable(self, height=len(info))
        i.show(ip, info)
        i.pack(fill=tk.BOTH)


class HostInfo(ttk.LabelFrame):
    def fill(self, info):
        h = HostTable(self, height=len(info["hosts"]))
        h.show(info["hosts"])
        h.pack(fill=tk.BOTH)


class MailInfo(ttk.LabelFrame):
    
    def fill(self, info):
        if len(info["mail"]) == 0:
            ttk.Label(self, text="No mail servers available", font=(None, 14)).pack()
            return
        m = MailTable(self, height=len(info["mail"]))
        m.show(info["mail"])
        m.pack(fill=tk.BOTH)


class AllInfo(ttk.Frame):

    def __init__(self, parent):
        super().__init__(parent)
        self._parent = parent

    def execute(self, host, serv, inverse):
        result = dns.connect_and_query(host, serv, inverse)
        if result.get("err") is not None:
            msgbox.showerror("Error", result.get("err"))
            self._parent.title("DNS Lookup Tool")
            return

        if not inverse:
            h = HostInfo(self, text="Host info")
            h.fill(result["result"])
            h.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10)

            m = MailInfo(self, text="Mail servers")
            m.fill(result["result"])
            m.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10)
        else:
            i = IPInfo(self, text="Information")
            i.fill(result["url"], result["result"])
            i.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10)


class Input(ttk.Frame):

    def __init__(self, parent):
        super().__init__(parent)
        self._parent = parent
        self._info = None

        grid = ttk.Frame(self)
        btns = ttk.Frame(self)
        lab = ttk.Label(self, text="DNS Lookup Tool", font=("Courier", 24))

        tk.Grid.columnconfigure(grid, 1, weight=1)
        tk.Grid.rowconfigure(grid, 0, weight=1)
        tk.Grid.columnconfigure(grid, 1, weight=1)

        ttk.Label(grid, text="Host name or IP: ", font=("Courier", 16), anchor=tk.E).grid(row=0, column=0, sticky=tk.E)
        ttk.Label(grid, text="DNS server: ", font=("Courier", 16), anchor=tk.E).grid(row=1, column=0, sticky=tk.E)
        self._host_inp = ttk.Entry(grid)
        self._serv_inp = ttk.Entry(grid)
        self._serv_inp.insert(tk.END, dns.get_default_dns())
        self._standard = ttk.Button(btns, text="Standard query", command=self.std_callback)
        self._inverse = ttk.Button(btns, text="Inverse query", command=self.inv_callback)

        self._host_inp.grid(row=0, column=1, pady=2, sticky=tk.E+tk.W)
        self._serv_inp.grid(row=1, column=1, pady=2, sticky=tk.E+tk.W)

        self._standard.pack(side=tk.LEFT, padx=5)
        self._inverse.pack(side=tk.LEFT, padx=5)

        lab.pack(side=tk.TOP, padx=5, pady=5)
        grid.pack(side=tk.TOP)
        btns.pack(side=tk.TOP, pady=10)

    def _callback(self, inverse):
        if self._host_inp.get() == "" or self._serv_inp.get() == "":
            msgbox.showerror("Error", "Missing input")
        if self._info is not None:
            self._info.pack_forget()
        if inverse:
            self._parent.title("Inverse query for " + self._host_inp.get())
        else:
            self._parent.title("Standard query for " + self._host_inp.get())
        self._info = AllInfo(self._parent)
        self._info.pack(side=tk.TOP, fill=tk.BOTH)
        self._info.execute(self._host_inp.get(), self._serv_inp.get(), inverse)

    def std_callback(self):
        self._callback(False)

    def inv_callback(self):
        self._callback(True)


class App:

    def __init__(self, root, pad=3):
        self._root = root
        self._root.title("DNS Lookup Tool")
        self._geom = '500x200+0+0'
        self._root.geometry(f"{self._root.winfo_screenwidth() - pad}x{self._root.winfo_screenheight() - pad}+0+0")
        self._root.bind('<Escape>', self.toggle_fullscreen)

        style = ttk.Style(root)
        style.theme_use("clam")

        main = Input(root)
        main.pack(side=tk.TOP, fill=tk.X)
        ttk.Frame().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

    def toggle_fullscreen(self, event):
        geom = self._root.winfo_geometry()
        self._root.geometry(self._geom)
        self._geom = geom


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
