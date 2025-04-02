import sys
import os
import hashlib
from datetime import datetime
from collections import defaultdict
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QListWidget, QLabel,
                             QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
                             QProgressBar, QSplitter, QCheckBox, QGroupBox)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPixmap, QColor
from PIL import Image
import magic


class DuplicateImageFinder(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Duplicate Image Finder")
        self.setMinimumSize(1600, 900)

        # Initialize variables
        self.directories = []
        self.image_files = []
        self.duplicate_groups = []
        self.file_to_duplicate_group = {}  # Maps file path to its duplicate group index

        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Create directory selection section
        dir_section = QWidget()
        dir_layout = QVBoxLayout(dir_section)

        # Directory list
        self.dir_list = QListWidget()
        dir_layout.addWidget(QLabel("Selected Directories:"))
        dir_layout.addWidget(self.dir_list)

        # Directory buttons
        dir_buttons = QHBoxLayout()
        add_dir_btn = QPushButton("Add Directory")
        remove_dir_btn = QPushButton("Remove Directory")
        add_dir_btn.clicked.connect(self.add_directory)
        remove_dir_btn.clicked.connect(self.remove_directory)
        dir_buttons.addWidget(add_dir_btn)
        dir_buttons.addWidget(remove_dir_btn)
        dir_layout.addLayout(dir_buttons)

        layout.addWidget(dir_section)

        # Create criteria selection section
        criteria_group = QGroupBox("Duplicate Detection Criteria")
        criteria_layout = QHBoxLayout()

        # Create checkboxes for each criterion
        self.name_check = QCheckBox("File Name")
        self.hash_check = QCheckBox("Hash")
        self.date_check = QCheckBox("Date")
        self.size_check = QCheckBox("Image Size")
        self.file_size_check = QCheckBox("File Size")

        # Set default checked state
        self.name_check.setChecked(True)
        self.hash_check.setChecked(True)
        self.date_check.setChecked(True)
        self.size_check.setChecked(True)
        self.file_size_check.setChecked(True)

        # Add checkboxes to layout
        criteria_layout.addWidget(self.name_check)
        criteria_layout.addWidget(self.hash_check)
        criteria_layout.addWidget(self.date_check)
        criteria_layout.addWidget(self.size_check)
        criteria_layout.addWidget(self.file_size_check)
        criteria_layout.addStretch()

        criteria_group.setLayout(criteria_layout)
        layout.addWidget(criteria_group)

        # Create status label
        self.status_label = QLabel("Ready to scan")
        layout.addWidget(self.status_label)

        # Create progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Create splitter for file lists and previews
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left side (First file list and preview)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        # First file list
        self.file_table1 = QTableWidget()
        self.file_table1.setColumnCount(13)
        self.file_table1.setHorizontalHeaderLabels([
            "File Name", "Path", "Size", "Created Date",
            "Modified Date", "Image Size", "Hash",
            "Name Match", "Hash Match", "Date Match",
            "Size Match", "File Size Match", "Action"
        ])
        self.file_table1.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.file_table1.itemSelectionChanged.connect(lambda: self.on_selection_changed(1))
        left_layout.addWidget(QLabel("File List 1:"))
        left_layout.addWidget(self.file_table1)

        # First preview
        self.preview_label1 = QLabel()
        self.preview_label1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_label1.setMinimumHeight(300)
        self.preview_label1.setStyleSheet("border: 1px solid #ccc;")
        left_layout.addWidget(QLabel("Preview 1:"))
        left_layout.addWidget(self.preview_label1)

        # Right side (Second file list and preview)
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        # Second file list
        self.file_table2 = QTableWidget()
        self.file_table2.setColumnCount(13)
        self.file_table2.setHorizontalHeaderLabels([
            "File Name", "Path", "Size", "Created Date",
            "Modified Date", "Image Size", "Hash",
            "Name Match", "Hash Match", "Date Match",
            "Size Match", "File Size Match", "Action"
        ])
        self.file_table2.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.file_table2.itemSelectionChanged.connect(lambda: self.on_selection_changed(2))
        right_layout.addWidget(QLabel("File List 2:"))
        right_layout.addWidget(self.file_table2)

        # Second preview
        self.preview_label2 = QLabel()
        self.preview_label2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_label2.setMinimumHeight(300)
        self.preview_label2.setStyleSheet("border: 1px solid #ccc;")
        right_layout.addWidget(QLabel("Preview 2:"))
        right_layout.addWidget(self.preview_label2)

        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

        # Create scan button
        scan_btn = QPushButton("Scan for Duplicates")
        scan_btn.clicked.connect(self.scan_duplicates)
        layout.addWidget(scan_btn)

    def add_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if dir_path and dir_path not in self.directories:
            self.directories.append(dir_path)
            self.dir_list.addItem(dir_path)

    def remove_directory(self):
        current_item = self.dir_list.currentItem()
        if current_item:
            dir_path = current_item.text()
            self.directories.remove(dir_path)
            self.dir_list.takeItem(self.dir_list.row(current_item))

    def get_image_info(self, file_path):
        try:
            with Image.open(file_path) as img:
                width, height = img.size
                return {
                    'width': width,
                    'height': height,
                    'size': os.path.getsize(file_path),
                    'created': datetime.fromtimestamp(os.path.getctime(file_path)),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)),
                    'hash': self.calculate_hash(file_path)
                }
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return None

    def calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def format_size(self, size_in_bytes):
        """Convert size in bytes to MB with 2 decimal places."""
        return f"{size_in_bytes / (1024 * 1024):.2f}"

    def get_selected_criteria(self):
        return {
            'name': self.name_check.isChecked(),
            'hash': self.hash_check.isChecked(),
            'date': self.date_check.isChecked(),
            'size': self.size_check.isChecked(),
            'file_size': self.file_size_check.isChecked()
        }

    def find_duplicates(self):
        # Group files by their hash first
        hash_groups = defaultdict(list)
        for file_info in self.image_files:
            hash_groups[file_info['hash']].append(file_info)
        
        # Find duplicates based on selected criteria
        duplicate_groups = []
        selected_criteria = self.get_selected_criteria()
        
        # Process each hash group
        for hash_value, files in hash_groups.items():
            if len(files) > 1:  # Only process groups with multiple files
                # Check each pair of files in the group
                for i in range(len(files)):
                    for j in range(i + 1, len(files)):
                        file1, file2 = files[i], files[j]
                        
                        # Check all selected criteria
                        matches = {
                            'name': file1['name'] == file2['name'],
                            'hash': file1['hash'] == file2['hash'],
                            'date': (abs((file1['created'] - file2['created']).total_seconds()) < 1 and
                                    abs((file1['modified'] - file2['modified']).total_seconds()) < 1),
                            'size': (file1['width'] == file2['width'] and file1['height'] == file2['height']),
                            'file_size': file1['size'] == file2['size']
                        }
                        
                        # Only consider matches for selected criteria
                        selected_matches = {k: v for k, v in matches.items() if selected_criteria[k]}
                        
                        # If all selected criteria match, add both files to duplicate groups
                        if all(selected_matches.values()):
                            if file1 not in duplicate_groups:
                                duplicate_groups.append(file1)
                            if file2 not in duplicate_groups:
                                duplicate_groups.append(file2)
        
        return duplicate_groups

    def scan_duplicates(self):
        # Check if at least one criterion is selected
        if not any(self.get_selected_criteria().values()):
            self.status_label.setText("Please select at least one criterion for duplicate detection")
            return

        self.file_table1.setRowCount(0)
        self.file_table2.setRowCount(0)
        self.image_files = []
        self.duplicate_groups = []
        self.file_to_duplicate_group = {}
        
        # Show progress bar and status
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Counting total files...")
        
        # First pass: Count total files
        total_files = 0
        for directory in self.directories:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    mime = magic.Magic(mime=True)
                    if mime.from_file(file_path).startswith('image/'):
                        total_files += 1
        
        if total_files == 0:
            self.status_label.setText("No image files found in selected directories")
            self.progress_bar.setVisible(False)
            return
        
        # Second pass: Process files
        processed_files = 0
        for directory in self.directories:
            for root, _, files in os.walk(directory):
                current_dir = os.path.basename(root)
                for file in files:
                    file_path = os.path.join(root, file)
                    self.status_label.setText(f"Scanning: {current_dir}/{file}")
                    mime = magic.Magic(mime=True)
                    if mime.from_file(file_path).startswith('image/'):
                        info = self.get_image_info(file_path)
                        if info:
                            info['path'] = file_path
                            info['name'] = file
                            self.image_files.append(info)
                        processed_files += 1
                        self.progress_bar.setValue(int((processed_files / total_files) * 100))
                        QApplication.processEvents()  # Update UI
        
        # Find duplicates
        self.status_label.setText("Finding duplicates...")
        self.duplicate_groups = self.find_duplicates()
        
        # Create duplicate groups mapping
        for i, file_info in enumerate(self.duplicate_groups):
            self.file_to_duplicate_group[file_info['path']] = i
        
        # Update tables
        self.status_label.setText("Updating file lists...")
        self.update_file_tables()
        
        # Final status
        self.status_label.setText(f"Scan complete. Found {len(self.image_files)} images, {len(self.duplicate_groups)} duplicates.")
        self.progress_bar.setVisible(False)

    def update_file_tables(self):
        # Update both tables with the same files
        for file_info in self.image_files:
            self.add_file_to_table(self.file_table1, file_info)
            self.add_file_to_table(self.file_table2, file_info)

    def add_file_to_table(self, table, file_info):
        row = table.rowCount()
        table.insertRow(row)
        
        # Set items
        table.setItem(row, 0, QTableWidgetItem(file_info['name']))
        table.setItem(row, 1, QTableWidgetItem(file_info['path']))
        table.setItem(row, 2, QTableWidgetItem(self.format_size(file_info['size'])))
        table.setItem(row, 3, QTableWidgetItem(str(file_info['created'])))
        table.setItem(row, 4, QTableWidgetItem(str(file_info['modified'])))
        table.setItem(row, 5, QTableWidgetItem(f"{file_info['width']}x{file_info['height']}"))
        table.setItem(row, 6, QTableWidgetItem(file_info['hash'][:8] + "..."))  # Show only first 8 characters
        
        # Check for matches with other files
        is_duplicate = file_info in self.duplicate_groups
        if is_duplicate:
            # Find matching criteria
            matches = {'name': False, 'hash': False, 'date': False, 'size': False, 'file_size': False}
            for other_file in self.image_files:
                if other_file != file_info and other_file in self.duplicate_groups:
                    if file_info['name'] == other_file['name']:
                        matches['name'] = True
                    if file_info['hash'] == other_file['hash']:
                        matches['hash'] = True
                    if (abs((file_info['created'] - other_file['created']).total_seconds()) < 1 and
                        abs((file_info['modified'] - other_file['modified']).total_seconds()) < 1):
                        matches['date'] = True
                    if (file_info['width'] == other_file['width'] and 
                        file_info['height'] == other_file['height']):
                        matches['size'] = True
                    if file_info['size'] == other_file['size']:
                        matches['file_size'] = True
            
            # Set match indicators
            table.setItem(row, 7, QTableWidgetItem("Yes" if matches['name'] else "No"))
            table.setItem(row, 8, QTableWidgetItem("Yes" if matches['hash'] else "No"))
            table.setItem(row, 9, QTableWidgetItem("Yes" if matches['date'] else "No"))
            table.setItem(row, 10, QTableWidgetItem("Yes" if matches['size'] else "No"))
            table.setItem(row, 11, QTableWidgetItem("Yes" if matches['file_size'] else "No"))
        else:
            # Set all match indicators to No for non-duplicates
            for col in range(7, 12):
                table.setItem(row, col, QTableWidgetItem("No"))
        
        # Add delete button
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(lambda checked, r=row, t=table: self.delete_file(r, t))
        table.setCellWidget(row, 12, delete_btn)
        
        # Set background color for duplicates
        if is_duplicate:
            for col in range(table.columnCount()):
                item = table.item(row, col)
                if item:
                    item.setBackground(QColor("#FFE5E5"))

    def on_selection_changed(self, table_number):
        # Get the selected file path
        table = self.file_table1 if table_number == 1 else self.file_table2
        selected_items = table.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        file_path = table.item(row, 1).text()
        
        # Update preview
        self.update_preview(table_number)
        
        # Find and highlight corresponding file in the other table
        other_table = self.file_table2 if table_number == 1 else self.file_table1
        for i in range(other_table.rowCount()):
            if other_table.item(i, 1).text() == file_path:
                other_table.selectRow(i)
                other_table.scrollToItem(other_table.item(i, 0))
                break
        
        # If this is a duplicate file, highlight all related duplicates
        if file_path in self.file_to_duplicate_group:
            group_index = self.file_to_duplicate_group[file_path]
            for i in range(other_table.rowCount()):
                other_file_path = other_table.item(i, 1).text()
                if other_file_path in self.file_to_duplicate_group:
                    if self.file_to_duplicate_group[other_file_path] == group_index:
                        other_table.selectRow(i)
                        other_table.scrollToItem(other_table.item(i, 0))

    def delete_file(self, row, table):
        file_path = table.item(row, 1).text()
        try:
            os.remove(file_path)
            # Remove from both tables
            for t in [self.file_table1, self.file_table2]:
                for i in range(t.rowCount()):
                    if t.item(i, 1).text() == file_path:
                        t.removeRow(i)
                        break
            
            # Update the image_files list and duplicate groups
            for file_info in self.image_files[:]:
                if file_info['path'] == file_path:
                    self.image_files.remove(file_info)
                    if file_info in self.duplicate_groups:
                        self.duplicate_groups.remove(file_info)
                    if file_path in self.file_to_duplicate_group:
                        del self.file_to_duplicate_group[file_path]
        except Exception as e:
            print(f"Error deleting file: {e}")

    def update_preview(self, preview_number):
        table = self.file_table1 if preview_number == 1 else self.file_table2
        preview_label = self.preview_label1 if preview_number == 1 else self.preview_label2
        
        selected_items = table.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        file_path = table.item(row, 1).text()
        
        try:
            pixmap = QPixmap(file_path)
            if not pixmap.isNull():
                # Calculate new size maintaining aspect ratio
                max_size = 640
                scaled_pixmap = pixmap.scaled(
                    max_size, max_size,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                preview_label.setPixmap(scaled_pixmap)
        except Exception as e:
            print(f"Error loading preview: {e}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DuplicateImageFinder()
    window.show()
    sys.exit(app.exec())
