import os
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from pathlib import Path
from typing import Dict, List, Set
from PIL import Image, ImageTk
import colorsys

class DuplicateFileChecker:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Duplicate File Checker")
        self.window.geometry("1200x800")
        
        # Create and configure the main frame
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initialize variables
        self.selected_dirs: List[str] = []
        self.duplicate_files: Dict[str, List[str]] = {}
        self.hash_colors: Dict[str, str] = {}
        self.pastel_colors = self.generate_pastel_colors(20)  # Generate 20 pastel colors
        
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
        ttk.Button(dir_frame, text="Clear Directories", command=self.clear_directories).pack(side=tk.LEFT, padx=5)
        
        # Directory list
        self.dir_listbox = tk.Listbox(dir_frame, height=3, width=100)
        self.dir_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Scan button
        ttk.Button(self.main_frame, text="Scan for Duplicates", command=self.scan_duplicates).grid(
            row=1, column=0, columnspan=2, pady=10)
        
        # Create frames for left and right file lists
        left_frame = ttk.LabelFrame(self.main_frame, text="File List 1", padding="5")
        left_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        right_frame = ttk.LabelFrame(self.main_frame, text="File List 2", padding="5")
        right_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        # Configure grid weights for frames
        left_frame.grid_columnconfigure(0, weight=1)
        left_frame.grid_rowconfigure(0, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(0, weight=1)
        
        # Create file lists
        self.tree1 = ttk.Treeview(left_frame, columns=("File Path", "Size", "Hash"), show="headings")
        self.tree1.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.tree2 = ttk.Treeview(right_frame, columns=("File Path", "Size", "Hash"), show="headings")
        self.tree2.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure treeview columns
        for tree in [self.tree1, self.tree2]:
            tree.heading("File Path", text="File Path")
            tree.heading("Size", text="Size (MB)")
            tree.heading("Hash", text="Hash")
            tree.column("File Path", width=300)
            tree.column("Size", width=100)
            tree.column("Hash", width=100)
        
        # Add scrollbars
        for frame, tree in [(left_frame, self.tree1), (right_frame, self.tree2)]:
            scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
            scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
            tree.configure(yscrollcommand=scrollbar.set)
        
        # Create image preview frames
        self.preview1 = ttk.LabelFrame(left_frame, text="Image Preview", padding="5")
        self.preview1.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.preview2 = ttk.LabelFrame(right_frame, text="Image Preview", padding="5")
        self.preview2.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Create image labels
        self.image_label1 = ttk.Label(self.preview1)
        self.image_label1.pack(expand=True)
        
        self.image_label2 = ttk.Label(self.preview2)
        self.image_label2.pack(expand=True)
        
        # Bind selection events
        self.tree1.bind('<<TreeviewSelect>>', lambda e: self.on_select(e, self.tree1, self.image_label1))
        self.tree2.bind('<<TreeviewSelect>>', lambda e: self.on_select(e, self.tree2, self.image_label2))
        
    def add_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            if directory not in self.selected_dirs:
                self.selected_dirs.append(directory)
                self.dir_listbox.insert(tk.END, directory)
    
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
        """Display image in the preview label."""
        try:
            if self.is_image_file(filepath):
                # Open and resize image
                image = Image.open(filepath)
                # Calculate aspect ratio
                aspect_ratio = image.width / image.height
                # Set maximum dimensions
                max_width = 300
                max_height = 200
                
                # Resize maintaining aspect ratio
                if aspect_ratio > 1:
                    new_width = min(max_width, image.width)
                    new_height = int(new_width / aspect_ratio)
                    if new_height > max_height:
                        new_height = max_height
                        new_width = int(new_height * aspect_ratio)
                else:
                    new_height = min(max_height, image.height)
                    new_width = int(new_height * aspect_ratio)
                    if new_width > max_width:
                        new_width = max_width
                        new_height = int(new_width / aspect_ratio)
                
                image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(image)
                label.configure(image=photo)
                label.image = photo  # Keep a reference
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
            self.display_image(filepath, image_label)
    
    def scan_duplicates(self):
        if not self.selected_dirs:
            messagebox.showerror("Error", "Please select at least one directory!")
            return
        
        # Clear previous results
        for tree in [self.tree1, self.tree2]:
            for item in tree.get_children():
                tree.delete(item)
        
        # Dictionary to store file hashes
        hash_dict: Dict[str, List[str]] = {}
        
        # Walk through all selected directories
        for directory in self.selected_dirs:
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        # Calculate file hash
                        file_hash = self.calculate_file_hash(filepath)
                        
                        # Add to hash dictionary
                        if file_hash in hash_dict:
                            hash_dict[file_hash].append(filepath)
                        else:
                            hash_dict[file_hash] = [filepath]
                    except Exception as e:
                        print(f"Error processing {filepath}: {str(e)}")
        
        # Assign colors to hashes
        self.hash_colors.clear()
        color_index = 0
        for file_hash in hash_dict:
            if len(hash_dict[file_hash]) > 1:
                self.hash_colors[file_hash] = self.pastel_colors[color_index % len(self.pastel_colors)]
                color_index += 1
        
        # Display results
        for file_hash, filepaths in hash_dict.items():
            if len(filepaths) > 1:  # Only show duplicates
                # Split files between the two trees
                mid_point = len(filepaths) // 2
                for i, filepath in enumerate(filepaths):
                    size = os.path.getsize(filepath)
                    values = (
                        filepath,
                        self.format_size(size),
                        file_hash[:8] + "..."  # Show only first 8 characters of hash
                    )
                    
                    # Add to appropriate tree
                    if i < mid_point:
                        item = self.tree1.insert("", tk.END, values=values)
                        if file_hash in self.hash_colors:
                            self.tree1.tag_configure(file_hash, background=self.hash_colors[file_hash])
                            self.tree1.item(item, tags=(file_hash,))
                    else:
                        item = self.tree2.insert("", tk.END, values=values)
                        if file_hash in self.hash_colors:
                            self.tree2.tag_configure(file_hash, background=self.hash_colors[file_hash])
                            self.tree2.item(item, tags=(file_hash,))
    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = DuplicateFileChecker()
    app.run()
