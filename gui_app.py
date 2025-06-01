import os
import time
import hashlib
import pickle

import datetime
import ttkbootstrap as tb
from tkinter import filedialog, messagebox

# Block class
class Block:
    def __init__(self, index, filename, file_hash, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.filename = filename
        self.file_hash = file_hash
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_content = f"{self.index}{self.timestamp}{self.filename}{self.file_hash}{self.previous_hash}"
        return hashlib.sha256(block_content.encode()).hexdigest()

# Blockchain class
class Blockchain:
    def __init__(self):
        self.chain = []

    def add_block(self, filename, file_hash):
        previous_hash = self.chain[-1].hash if self.chain else "0"
        block = Block(len(self.chain), filename, file_hash, previous_hash)
        self.chain.append(block)

    def save_to_file(self, path="blockchain_data.pkl"):
        with open(path, "wb") as f:
            pickle.dump(self.chain, f)

    def load_from_file(self, path="blockchain_data.pkl"):
        if os.path.exists(path):
            with open(path, "rb") as f:
                self.chain = pickle.load(f)

# Utility function to compute SHA256 hash of a file
def compute_file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

# GUI App using ttkbootstrap
class FileIntegrityApp:
    def __init__(self, master):
        self.master = master
        master.title("Blockchain-Based File Integrity Checker")
        master.geometry("1000x520")

        self.blockchain = Blockchain()
        self.blockchain.load_from_file()

        # Define custom style for buttons with font
        style = tb.Style()
        button_font = ("Helvetica", 12, "bold")
        style.configure('Custom.TButton', font=button_font)

        # Frame for buttons
        button_frame = tb.Frame(master)
        button_frame.pack(pady=10, fill="x")

        tb.Button(button_frame, text="Add File", bootstyle="primary Custom.TButton", command=self.add_file, width=15).pack(side="left", padx=5)
        tb.Button(button_frame, text="Add Folder", bootstyle="primary Custom.TButton", command=self.add_folder, width=15).pack(side="left", padx=5)
        tb.Button(button_frame, text="Check Integrity", bootstyle="success Custom.TButton", command=self.check_integrity, width=18).pack(side="left", padx=5)
        tb.Button(button_frame, text="Export Report", bootstyle="info Custom.TButton", command=self.export_report, width=15).pack(side="left", padx=5)
        tb.Button(button_frame, text="Blockchain View", bootstyle="secondary Custom.TButton", command=self.open_blockchain_view, width=18).pack(side="left", padx=5)
        tb.Button(button_frame, text="Remove File", bootstyle="warning Custom.TButton", command=self.remove_file, width=15).pack(side="left", padx=5)
        tb.Button(button_frame, text="Remove All Files", bootstyle="danger Custom.TButton", command=self.remove_all_files, width=18).pack(side="left", padx=5)

        # Treeview for files
        tree_frame = tb.Frame(master)
        tree_frame.pack(padx=10, pady=10, fill="both", expand=True)

        columns = ("Name", "Hash", "Status")
        # Removed bootstyle="info" from Treeview
        self.tree = tb.Treeview(tree_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            if col == "Status":
                self.tree.column(col, anchor="center", width=150)  # Center-align Status column
            elif col == "Hash":
                self.tree.column(col, anchor="w", width=250)      # Left-align Hash column
            else:
                self.tree.column(col, anchor="w", width=150)      # Left-align Name column

        scrollbar = tb.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        self.load_existing_data_into_table()

    def load_existing_data_into_table(self):
        self.tree.delete(*self.tree.get_children())
        for block in self.blockchain.chain:
            self.tree.insert("", "end", values=(os.path.basename(block.filename), block.file_hash, "UNCHANGED"))

    def add_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        if any(block.filename == file_path for block in self.blockchain.chain):
            messagebox.showinfo("Info", "File already added.")
            return

        file_hash = compute_file_hash(file_path)
        if file_hash is None:
            messagebox.showerror("Error", "Failed to read file.")
            return

        self.blockchain.add_block(file_path, file_hash)
        self.blockchain.save_to_file()
        self.tree.insert("", "end", values=(os.path.basename(file_path), file_hash, "ADDED"))

    def add_folder(self):
        folder_path = filedialog.askdirectory()
        if not folder_path:
            return

        added_any = False
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if any(block.filename == file_path for block in self.blockchain.chain):
                    continue
                file_hash = compute_file_hash(file_path)
                if file_hash is None:
                    continue
                self.blockchain.add_block(file_path, file_hash)
                self.tree.insert("", "end", values=(os.path.basename(file_path), file_hash, "ADDED"))
                added_any = True

        if added_any:
            self.blockchain.save_to_file()
        else:
            messagebox.showinfo("Info", "No new files added from folder.")

    def check_integrity(self):
        for i, block in enumerate(self.blockchain.chain):
            current_hash = compute_file_hash(block.filename)
            if current_hash is None:
                status = "MISSING"
            elif current_hash == block.file_hash:
                status = "UNCHANGED"
            else:
                status = "TAMPERED"
                messagebox.showwarning("Tampering Detected", f"File '{os.path.basename(block.filename)}' has been tampered.")
            self.tree.item(self.tree.get_children()[i], values=(os.path.basename(block.filename), block.file_hash, status))

    def remove_file(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a file to remove.")
            return

        item_id = selected[0]
        item = self.tree.item(item_id)
        filename = item['values'][0]

        index_to_remove = next((i for i, block in enumerate(self.blockchain.chain) if os.path.basename(block.filename) == filename), None)
        if index_to_remove is not None:
            del self.blockchain.chain[index_to_remove]
            self.blockchain.save_to_file()
            self.tree.delete(item_id)
            messagebox.showinfo("Success", f"Removed '{filename}' from blockchain.")
        else:
            messagebox.showwarning("Warning", "File not found in blockchain.")

    def remove_all_files(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to remove ALL files from the blockchain?"):
            self.blockchain.chain.clear()
            self.blockchain.save_to_file()
            self.tree.delete(*self.tree.get_children())
            messagebox.showinfo("Success", "All files removed from blockchain.")

    def open_blockchain_view(self):
        view_window = tb.Toplevel(self.master)
        view_window.title("Blockchain Structure")
        view_window.geometry("600x500")

        text_frame = tb.Frame(view_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar = tb.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")

        text_widget = tb.Text(text_frame, wrap="none", yscrollcommand=scrollbar.set, font=("Helvetica", 12))
        text_widget.pack(fill="both", expand=True)
        scrollbar.config(command=text_widget.yview)

        for block in self.blockchain.chain:
            timestamp_str = datetime.datetime.fromtimestamp(block.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            block_info = (
                f"Index: {block.index}\n"
                f"Filename: {os.path.basename(block.filename)}\n"
                f"File Hash: {block.file_hash}\n"
                f"Previous Hash: {block.previous_hash}\n"
                f"Block Hash: {block.hash}\n"
                f"Timestamp: {timestamp_str}\n"
                f"{'-'*60}\n"
            )
            text_widget.insert("end", block_info)
        text_widget.config(state="disabled")

    def export_report(self):
        export_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
        if not export_path:
            return
        try:
            with open(export_path, "w") as f:
                f.write("Filename\tHash\tStatus\n")
                for item_id in self.tree.get_children():
                    values = self.tree.item(item_id, "values")
                    f.write(f"{values[0]}\t{values[1]}\t{values[2]}\n")
            messagebox.showinfo("Exported", f"Report saved to:\n{export_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report.\n{e}")

if __name__ == "__main__":
    root = tb.Window(themename="superhero")
    app = FileIntegrityApp(root)
    root.mainloop()
