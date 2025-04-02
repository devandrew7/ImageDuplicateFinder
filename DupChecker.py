import os
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from typing import Dict, List
from PIL import Image, ImageTk
import colorsys
import datetime
import time

class DuplicateFileChecker:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Duplicate File Checker")
        self.window.geometry("1600x900")  # Made wider for full file paths
        
        # Create and configure the main frame
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initialize variables
        self.selected_dirs: List[str] = []
        self.duplicate_files: Dict[str, List[str]] = {}
        self.hash_colors: Dict[str, str] = {}
        self.pastel_colors = self.generate_pastel_colors(20)  # Generate 20 pastel colors
        
        # Add progress bar variable
        self.progress_var = tk.DoubleVar()
        self.last_progress_update = time.time()
        
        # Configure grid weights
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)
        
        # Create widgets
        self.create_widgets()
        
    def generate_pastel_colors(self, n: int) -> List[str]:
        """Generate n pastel colors."""
        colors = []
        for i in range(n):
            # Generate base color in HSV
            hue = i / n
            saturation = 0.3
            value = 0.95
            # Convert to RGB
            rgb = colorsys.hsv_to_rgb(hue, saturation, value)
            # Convert to hex color code
            color = '#{:02x}{:02x}{:02x}'.format(
                int(rgb[0] * 255),
                int(rgb[1] * 255),
                int(rgb[2] * 255)
            )
            colors.append(color)
        return colors
        
    def create_widgets(self):
        # Directory selection frame
        dir_frame = ttk.LabelFrame(self.main_frame, text="Directory Selection", padding="5")
        dir_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(dir_frame, text="Add Directory", command=self.add_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(dir_frame, text="Remove Selected", command=self.remove_selected_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(dir_frame, text="Clear All", command=self.clear_directories).pack(side=tk.LEFT, padx=5)
        
        # Directory list
        self.dir_listbox = tk.Listbox(dir_frame, height=3, width=100)
        self.dir_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Scan button
        ttk.Button(self.main_frame, text="Scan for Duplicates", command=self.scan_duplicates).grid(
            row=1, column=0, columnspan=2, pady=10)
        
        # Create frames for left and right file lists
        left_frame = ttk.LabelFrame(self.main_frame, text="Duplicate Files View 1", padding="5")
        left_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        right_frame = ttk.LabelFrame(self.main_frame, text="Duplicate Files View 2", padding="5")
        right_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        # Configure grid weights for frames
        left_frame.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(0, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(0, weight=1)
        
        # Create file lists
        self.tree1 = ttk.Treeview(left_frame, columns=("File Path", "Size", "Created", "Modified", "Hash"), show="headings")
        self.tree1.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.tree2 = ttk.Treeview(right_frame, columns=("File Path", "Size", "Created", "Modified", "Hash"), show="headings")
        self.tree2.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure treeview columns
        for tree in [self.tree1, self.tree2]:
            tree.configure(columns=("File Path", "Size", "Created", "Modified", "Hash"))
            tree.heading("File Path", text="File Path")
            tree.heading("Size", text="Size (MB)")
            tree.heading("Created", text="Created")
            tree.heading("Modified", text="Modified")
            tree.heading("Hash", text="Hash")
            tree.column("File Path", width=500, stretch=True)  # Make file path column wider and stretchable
            tree.column("Size", width=100, stretch=False)
            tree.column("Created", width=150, stretch=False)
            tree.column("Modified", width=150, stretch=False)
            tree.column("Hash", width=100, stretch=False)
        
        # Add scrollbars
        for frame, tree in [(left_frame, self.tree1), (right_frame, self.tree2)]:
            scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
            scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
            tree.configure(yscrollcommand=scrollbar.set)
        
        # Add Delete Selected buttons below each tree
        ttk.Button(left_frame, text="Delete Selected", 
            command=lambda: self.delete_selected(self.tree1)).grid(row=1, column=0, pady=5)
        ttk.Button(right_frame, text="Delete Selected", 
            command=lambda: self.delete_selected(self.tree2)).grid(row=1, column=0, pady=5)

        # Move preview frames one row down
        self.preview1 = ttk.LabelFrame(left_frame, text="Image Preview", padding="5")
        self.preview1.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.preview2 = ttk.LabelFrame(right_frame, text="Image Preview", padding="5")
        self.preview2.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Create image labels
        self.image_label1 = ttk.Label(self.preview1)
        self.image_label1.pack(expand=True)
        
        self.image_label2 = ttk.Label(self.preview2)
        self.image_label2.pack(expand=True)
        
        # Bind selection events
        self.tree1.bind('<<TreeviewSelect>>', lambda e: self.on_select(e, self.tree1, self.image_label1))
        self.tree2.bind('<<TreeviewSelect>>', lambda e: self.on_select(e, self.tree2, self.image_label2))
        
        # Double the max preview dimensions
        self.max_preview_width = 600
        self.max_preview_height = 400

        # Modify progress bar label
        progress_frame = ttk.Frame(self.main_frame)
        progress_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.progress_label = ttk.Label(progress_frame, text="")
        self.progress_label.pack(pady=2)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame, 
            orient="horizontal", 
            length=300, 
            mode="determinate",
            variable=self.progress_var
        )
        self.progress_bar.pack(fill=tk.X, padx=5)
        
        # Add red text tag configuration
        self.tree2.tag_configure("selected_duplicate", foreground="red")
        
    def add_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            if directory not in self.selected_dirs:
                self.selected_dirs.append(directory)
                self.dir_listbox.insert(tk.END, directory)
    
    def remove_selected_directory(self):
        selection = self.dir_listbox.curselection()
        if selection:
            index = selection[0]
            directory = self.dir_listbox.get(index)
            self.selected_dirs.remove(directory)
            self.dir_listbox.delete(index)
    
    def clear_directories(self):
        self.selected_dirs.clear()
        self.dir_listbox.delete(0, tk.END)
    
    def calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def format_size(self, size_in_bytes: int) -> str:
        """Convert size in bytes to MB with 2 decimal places."""
        return f"{size_in_bytes / (1024 * 1024):.2f}"
    
    def get_file_extension(self, filepath: str) -> str:
        """Get file extension in lowercase."""
        return os.path.splitext(filepath)[1].lower()
    
    def is_image_file(self, filepath: str) -> bool:
        """Check if file is an image."""
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}
        return self.get_file_extension(filepath) in image_extensions
    
    def display_image(self, filepath: str, label: ttk.Label):
        """Display image in the preview label with doubled dimensions."""
        try:
            if self.is_image_file(filepath):
                image = Image.open(filepath)
                aspect_ratio = image.width / image.height
                
                # Use doubled maximum dimensions
                if aspect_ratio > 1:
                    new_width = min(self.max_preview_width, image.width)
                    new_height = int(new_width / aspect_ratio)
                    if new_height > self.max_preview_height:
                        new_height = self.max_preview_height
                        new_width = int(new_height * aspect_ratio)
                else:
                    new_height = min(self.max_preview_height, image.height)
                    new_width = int(new_height * aspect_ratio)
                    if new_width > self.max_preview_width:
                        new_width = self.max_preview_width
                        new_height = int(new_width / aspect_ratio)
                
                image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(image)
                label.configure(image=photo)
                label.image = photo
            else:
                label.configure(image='')
                label.image = None
        except Exception as e:
            label.configure(image='')
            label.image = None
            print(f"Error displaying image {filepath}: {str(e)}")
    
    def on_select(self, event, tree, image_label):
        """Handle file selection event."""
        selection = tree.selection()
        if selection:
            filepath = tree.item(selection[0])['values'][0]
            file_hash = tree.item(selection[0])['values'][4]
            self.display_image(filepath, image_label)
            
            # If selection is from tree1, highlight and scroll to matching item in tree2
            if tree == self.tree1:
                # Remove previous red highlight from tree2
                for item in self.tree2.get_children():
                    current_tags = list(self.tree2.item(item)['tags'])
                    if 'selected_duplicate' in current_tags:
                        current_tags.remove('selected_duplicate')
                        self.tree2.item(item, tags=current_tags)
                
                # Deselect any current selection in tree2
                self.tree2.selection_remove(self.tree2.selection())
                
                # Find and select matching item in tree2
                for item in self.tree2.get_children():
                    if self.tree2.item(item)['values'][4] == file_hash:
                        # Select the item
                        self.tree2.selection_add(item)
                        # Add red highlight
                        current_tags = list(self.tree2.item(item)['tags'])
                        current_tags.append('selected_duplicate')
                        self.tree2.item(item, tags=current_tags)
                        # Scroll to make the item visible
                        self.tree2.see(item)
                        break
    
    def delete_selected(self, tree):
        """Delete selected files using Windows recycle bin."""
        selection = tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No files selected")
            return
        
        import ctypes
        from ctypes import wintypes
        
        # Windows API constants
        FOF_SILENT = 4
        FOF_NOCONFIRMATION = 16
        FOF_ALLOWUNDO = 64
        FOF_NOERRORUI = 1024
        
        # Structure for file operation
        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND),
                ("wFunc", wintypes.UINT),
                ("pFrom", wintypes.LPCWSTR),
                ("pTo", wintypes.LPCWSTR),
                ("fFlags", wintypes.WORD),
                ("fAnyOperationsAborted", wintypes.BOOL),
                ("hNameMappings", wintypes.LPVOID),
                ("lpszProgressTitle", wintypes.LPCWSTR),
            ]
        
        for item in selection:
            filepath = tree.item(item)['values'][0]
            try:
                # Prepare the file path for Windows API
                filepath = os.path.abspath(filepath)
                # Double null-terminate the string as required by Windows API
                filepath = filepath + '\0'
                
                # Set up the file operation structure
                fileop = SHFILEOPSTRUCTW()
                fileop.wFunc = 3  # FO_DELETE
                fileop.pFrom = filepath
                fileop.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT
                
                # Perform the operation
                shell32 = ctypes.windll.shell32
                result = shell32.SHFileOperationW(ctypes.byref(fileop))
                
                if result == 0:  # Success
                    # Remove item from both trees
                    item_values = tree.item(item)['values']
                    file_hash = item_values[4]  # Get hash from values
                    
                    # Remove from both trees
                    for t in [self.tree1, self.tree2]:
                        for child in t.get_children():
                            if t.item(child)['values'][4] == file_hash:
                                t.delete(child)
                else:
                    raise Exception(f"Operation failed with code {result}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {filepath}: {str(e)}")

    def scan_duplicates(self):
        if not self.selected_dirs:
            messagebox.showerror("Error", "Please select at least one directory!")
            return
        
        # Clear previous results
        for tree in [self.tree1, self.tree2]:
            for item in tree.get_children():
                tree.delete(item)
        
        # Reset progress
        self.progress_var.set(0)
        self.progress_label.config(text="Counting files...")
        self.window.update()
        
        # Count only image files
        total_files = 0
        for d in self.selected_dirs:
            for root, _, files in os.walk(d):
                for filename in files:
                    if self.is_image_file(os.path.join(root, filename)):
                        total_files += 1
        
        if total_files == 0:
            messagebox.showinfo("Info", "No image files found in selected directories")
            return
        
        hash_dict: Dict[str, List[str]] = {}
        processed_files = 0
        
        for directory in self.selected_dirs:
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Skip non-image files
                    if not self.is_image_file(filepath):
                        continue
                    
                    try:
                        file_hash = self.calculate_file_hash(filepath)
                        
                        if file_hash in hash_dict:
                            hash_dict[file_hash].append(filepath)
                        else:
                            hash_dict[file_hash] = [filepath]
                        
                        processed_files += 1
                        current_time = time.time()
                        if current_time - self.last_progress_update >= 5:
                            progress = (processed_files / total_files) * 100
                            self.progress_var.set(progress)
                            self.progress_label.config(
                                text=f"Processing: {processed_files} / {total_files} files ({progress:.1f}%)"
                            )
                            self.window.update()
                            self.last_progress_update = current_time
                            
                    except Exception as e:
                        print(f"Error processing {filepath}: {str(e)}")
        
        # Update display with dates - show all duplicates in both trees
        for file_hash, filepaths in hash_dict.items():
            if len(filepaths) > 1:  # Only show duplicates
                # Add color for this hash group
                if file_hash not in self.hash_colors:
                    color_index = len(self.hash_colors) % len(self.pastel_colors)
                    self.hash_colors[file_hash] = self.pastel_colors[color_index]
                
                # Add all files to both trees
                for filepath in filepaths:
                    stats = os.stat(filepath)
                    created = datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M')
                    modified = datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M')
                    
                    values = (
                        filepath,
                        self.format_size(stats.st_size),
                        created,
                        modified,
                        file_hash[:8] + "..."
                    )
                    
                    # Insert into both trees with background color only
                    for tree in [self.tree1, self.tree2]:
                        item = tree.insert("", tk.END, values=values)
                        tree.tag_configure(file_hash, background=self.hash_colors[file_hash])
                        tree.item(item, tags=(file_hash,))

        # Update final count - show total groups of duplicates
        duplicate_groups = sum(1 for filepaths in hash_dict.values() if len(filepaths) > 1)
        self.progress_var.set(100)
        self.progress_label.config(
            text=f"Completed: Found {duplicate_groups} groups of duplicate images"
        )

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = DuplicateFileChecker()
    app.run()
