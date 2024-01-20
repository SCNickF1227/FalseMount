import subprocess
import ipaddress
import logging
import traceback
import socket
from zeroconf import ServiceBrowser, Zeroconf, ServiceListener

# GUI imports
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

# Setup logger
logger = logging.getLogger('SMBDiscovery')
logger.setLevel(logging.INFO)
log_file_handler = logging.FileHandler('smb_discovery.log')
log_file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file_handler.setFormatter(formatter)
logger.addHandler(log_file_handler)

class SMBListener(ServiceListener):
    def __init__(self, update_callback):
        self.servers = {}
        self.update_callback = update_callback

    def remove_service(self, zeroconf, service_type, name):
        service_name = name.split('.')[0]
        if service_name in self.servers:
            del self.servers[service_name]
            logger.info(f"Service {service_name} removed")
            self.update_callback(self.servers)

    def add_service(self, zeroconf, service_type, name):
        info = zeroconf.get_service_info(service_type, name)
        if info:
            service_name = name.split('.')[0]
            addresses = [str(ipaddress.ip_address(addr)) for addr in info.parsed_addresses() if ':' not in addr]
            self.servers[service_name] = addresses
            logger.info(f"Service {service_name} added, address(es): {addresses}")
            self.update_callback(self.servers)

def get_mounted_shares_mapping():
    try:
        output = subprocess.check_output("net use", shell=True).decode()
        lines = output.splitlines()
        mapping = {}
        for line in lines:
            if 'Microsoft Windows Network' in line:
                parts = line.split()
                local_drive = parts[1]
                remote_share = parts[2]
                mapping[remote_share.lower()] = local_drive.lower()
        return mapping
    except subprocess.CalledProcessError:
        return {}

def list_shares_on_server(server_ip):
    try:
        raw_output = subprocess.check_output(f"net view \\\\{server_ip}", shell=True).decode()
        shares = parse_net_view_output(raw_output)
        mounted_shares_mapping = get_mounted_shares_mapping()
        shares_with_status = []
        for share_name, _ in shares:
            remote_path = f"\\\\{server_ip}\\{share_name}".lower()
            if remote_path in mounted_shares_mapping:
                mounted_drive = mounted_shares_mapping[remote_path]
                shares_with_status.append((share_name, 'Mounted', mounted_drive))
            else:
                shares_with_status.append((share_name, 'Not Mounted', None))
        return shares_with_status
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to list shares on server {server_ip}: {e}")
        traceback.print_exc()
        return []

def parse_net_view_output(output):
    lines = output.splitlines()
    share_lines = []
    for line in lines:
        if 'Disk' in line:
            parts = line.split()
            share_name = parts[0]
            share_lines.append((share_name, 'Disk'))
    return share_lines

    def mount_share(self):
        share_selection = self.shares_list.curselection()

        if not share_selection:
            messagebox.showwarning("Warning", "Please select a share.")
            return

        selected_share = self.shares_list.get(share_selection[0]).split(" - ")[0]
        if not hasattr(self, 'selected_server') or not self.selected_server:
            messagebox.showwarning("Warning", "Server not selected. Please perform a scan and select a server.")
            return

        address = self.listener.servers[self.selected_server][0]
        share_path = f"\\\\{address}\\{selected_share}"
        drive_letter = self.drive_letter_var.get()

        if drive_letter:
            # Check if the drive letter is already in use
            if drive_letter in self.get_mounted_shares_mapping().values():
                response = messagebox.askyesno("Drive Letter in Use",
                                               f"The drive letter {drive_letter} is already in use. "
                                               "Would you like to unmount it?")
                if response:
                    # Attempt to unmount the current share
                    self.unmount_share(drive_letter)
                else:
                    return  # User chose not to unmount the drive

            try:
                self.perform_mount(share_path, drive_letter)
                messagebox.showinfo("Success", f"Share {selected_share} mounted to {drive_letter} successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to mount share: {e}")
        else:
            messagebox.showinfo("Info", "Please select a drive letter.")

    def unmount_share(self, drive_letter):
        try:
            subprocess.run(["net", "use", drive_letter, "/delete"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info(f"Unmounted {drive_letter}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unmount {drive_letter}: {e}")
            messagebox.showerror("Error", f"Failed to unmount drive {drive_letter}: {e}")

def list_mounted_drives():
    try:
        output = subprocess.check_output("net use", shell=True).decode()
        lines = output.splitlines()
        mounted_drives = []
        for line in lines:
            if 'OK' in line:
                parts = line.split()
                if len(parts) > 2 and parts[1].endswith(':'):
                    mounted_drives.append(parts[1])
        return mounted_drives
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to list mounted drives: {e}")
        traceback.print_exc()
        return []

def get_used_drive_letters():
    # Use the 'wmic' command to list all the logical drives in the system (Windows-specific)
    result = subprocess.run(['wmic', 'logicaldisk', 'get', 'name'], capture_output=True, text=True)
    # The result.stdout will be a string with drive letters followed by ':', we just want the letter
    used_drives = [line.strip() for line in result.stdout.split('\n') if ':' in line]
    # Extract just the drive letter from 'X:' to 'X'
    used_drives = [drive.replace(':', '') for drive in used_drives]
    return used_drives

class SMBDiscoveryGUI:
    def __init__(self, root):
        self.root = root
        root.title("FALSEMount: An SMB Share Discovery Tool")

        # Setup Zeroconf
        self.zeroconf = Zeroconf()

        # Create an SMBListener instance with a callback to update the server list
        self.listener = SMBListener(self.update_server_list)

        # GUI elements setup
        tk.Label(root, text="Servers with SMB Shares Found").grid(row=0, column=0)
        self.scan_button = tk.Button(root, text="Scan for SMB Servers", command=self.scan_servers)
        self.scan_button.grid(row=1, column=0, columnspan=2, sticky="ew")

        tk.Label(root, text="SMB Shares").grid(row=0, column=1)
        
        # Configure the columns to take the full available width
        root.grid_columnconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=1)
        
        # Server List with a horizontal scrollbar
        self.server_list_frame = tk.Frame(root)
        self.server_list_frame.grid(row=2, column=0, sticky="nsew")
        self.server_list = tk.Listbox(self.server_list_frame, width=50)
        self.server_list.pack(side="left", fill="y")
        server_list_scrollbar = tk.Scrollbar(self.server_list_frame, orient="vertical", command=self.server_list.yview)
        server_list_scrollbar.pack(side="right", fill="y")
        self.server_list['yscrollcommand'] = server_list_scrollbar.set
        self.server_list.bind("<<ListboxSelect>>", self.on_server_select)

        # Shares List with a horizontal scrollbar
        self.shares_list_frame = tk.Frame(root)
        self.shares_list_frame.grid(row=2, column=1, sticky="nsew")
        self.shares_list = tk.Listbox(self.shares_list_frame, width=50)
        self.shares_list.pack(side="left", fill="y")
        shares_list_scrollbar = tk.Scrollbar(self.shares_list_frame, orient="vertical", command=self.shares_list.yview)
        shares_list_scrollbar.pack(side="right", fill="y")
        self.shares_list['yscrollcommand'] = shares_list_scrollbar.set

        self.drive_letter_var = tk.StringVar()
        used_drive_letters = get_used_drive_letters()
        available_drive_letters = [f"{chr(i)}:" for i in range(65, 91) if f"{chr(i)}" not in used_drive_letters]
        self.drive_letter_dropdown = ttk.Combobox(root, textvariable=self.drive_letter_var, values=available_drive_letters)
        self.drive_letter_dropdown.grid(row=3, column=0, columnspan=2, sticky="ew")

        self.mount_button = tk.Button(root, text="Mount Share", command=self.mount_share)
        self.mount_button.grid(row=4, column=0, sticky="ew")

        self.unmount_button = tk.Button(root, text="Unmount Share", command=self.unmount_selected_share)
        self.unmount_button.grid(row=4, column=1, sticky="ew")

        self.exit_button = tk.Button(root, text="Exit", command=self.close_app)
        self.exit_button.grid(row=5, column=0, columnspan=2, sticky="ew")

    def scan_servers(self):
        self.browser = ServiceBrowser(self.zeroconf, "_smb._tcp.local.", self.listener)
        self.server_list.delete(0, tk.END)

    def update_server_list(self, servers):
        self.server_list.delete(0, tk.END)
        for server in servers:
            self.server_list.insert(tk.END, server)

    def get_selected_drive_letter(self):
        share_selection = self.shares_list.curselection()
        if share_selection:
            share_info = self.shares_list.get(share_selection[0])
            # Assuming the share_info is in the format "ShareName - Status on DRIVE_LETTER"
            parts = share_info.split(" on ")
            if len(parts) > 1 and parts[1].endswith(':'):
                return parts[1].strip(':')
            else:
                messagebox.showwarning("Warning", "No mounted drive letter found for the selected share.")
                return None
        else:
            messagebox.showwarning("Warning", "Please select a share first.")
            return None
        
    def on_server_select(self, event):
        selection = event.widget.curselection()
        if selection:
            self.selected_server = event.widget.get(selection[0])
            addresses = self.listener.servers[self.selected_server]
            selected_address = addresses[0] if addresses else None
            if selected_address:
                shares = list_shares_on_server(selected_address)
                self.update_shares_list(shares)

    def update_shares_list(self, shares):
        self.shares_list.delete(0, tk.END)
        for share, status, drive in shares:
            share_info = f"{share} - {status}"
            if drive:
                share_info += f" on {drive}"
            self.shares_list.insert(tk.END, share_info)

    def mount_share(self):
        share_selection = self.shares_list.curselection()

        if not share_selection:
            messagebox.showwarning("Warning", "Please select a share.")
            return

        selected_share = self.shares_list.get(share_selection[0]).split(" - ")[0]
        if not hasattr(self, 'selected_server') or not self.selected_server:
            messagebox.showwarning("Warning", "Server not selected. Please perform a scan and select a server.")
            return

        address = self.listener.servers[self.selected_server][0]
        share_path = f"\\\\{address}\\{selected_share}"
        drive_letter = self.drive_letter_var.get()

        if drive_letter:
            try:
                self.perform_mount(share_path, drive_letter)
                messagebox.showinfo("Success", f"Share {selected_share} mounted to {drive_letter} successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to mount share: {e}")
        else:
            messagebox.showinfo("Info", "Please select a drive letter.")

    def unmount_share(self, drive_letter):
        try:
            subprocess.run(["net", "use", drive_letter, "/delete"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info(f"Unmounted {drive_letter}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unmount {drive_letter}: {e}")
            messagebox.showerror("Error", f"Failed to unmount drive {drive_letter}: {e}")
    def unmount_selected_share(self):
            drive_letter = self.get_selected_drive_letter()
            if drive_letter:
                self.unmount_share(drive_letter)

    def perform_mount(self, share_path, drive_letter):
        command = ["net", "use", drive_letter, share_path]
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Mounted {share_path} to {drive_letter}")

    def close_app(self):
        self.zeroconf.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    gui = SMBDiscoveryGUI(root)
    root.mainloop()
