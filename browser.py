import sys
import hashlib
import re
import requests
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                            QWidget, QPushButton, QLineEdit, QTextEdit, QLabel, 
                            QSplitter, QTabWidget, QSpinBox, QGroupBox, QGridLayout,
                            QProgressBar, QStatusBar, QMessageBox, QFileDialog,
                            QCheckBox, QTextBrowser, QScrollArea, QFrame)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QUrl
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap, QDesktopServices
from bs4 import BeautifulSoup
import urllib.parse

class HashMapper:
    def __init__(self, table_size=10000):
        """Initialize the hash mapper with a fixed table size."""
        self.table_size = table_size
        self.table = [None] * table_size
        self.word_to_index = {}
        self.index_to_word = {}

    def _compute_hash(self, word):
        """Compute initial hash index for the word using SHA-256."""
        sha_digest = hashlib.sha256(word.encode('utf-8')).hexdigest()
        int_hash = int(sha_digest, 16)
        return int_hash % self.table_size

    def _compute_step(self, word):
        """Compute a probing step derived from the SHA-256 hash."""
        sha_digest = hashlib.sha256(word.encode('utf-8')).hexdigest()
        int_hash = int(sha_digest, 16)
        step = 1 + (int_hash // self.table_size) % (self.table_size - 1)
        return step

    def insert(self, word):
        """Insert a word into the hash table using linear probing."""
        if word in self.word_to_index:
            return
        
        index = self._compute_hash(word)
        original_index = index
        probe = 0
        
        while self.table[index] is not None:
            probe += 1
            index = (original_index + probe) % self.table_size
            if probe >= self.table_size:
                raise ValueError("Hash table is full! Increase table_size.")
        
        self.table[index] = word
        self.word_to_index[word] = index
        self.index_to_word[index] = word

    def insert_words(self, words):
        """Insert a list of words."""
        for word in words:
            if word and word.strip():
                self.insert(word.strip().lower())

    def find_encrypted_word(self, word):
        """Find the encrypted version of a word using hash-derived probing."""
        word = word.lower().strip()
        if word not in self.word_to_index:
            return None
        
        hash_index = self._compute_hash(word)
        step = self._compute_step(word)
        probe_index = (hash_index + step) % self.table_size
        start_probe = probe_index
        
        attempts = 0
        while attempts < self.table_size:
            if (self.table[probe_index] is not None and 
                self.table[probe_index] != word):
                return self.table[probe_index]
            
            probe_index = (probe_index + step) % self.table_size
            attempts += 1
            
            if probe_index == start_probe:
                break
        
        return None

    def get_encryption_mapping(self, words):
        """Get encryption mapping for a list of words."""
        mapping = {}
        for word in set(words):
            encrypted = self.find_encrypted_word(word)
            if encrypted:
                mapping[word.lower()] = encrypted
        return mapping

class WebContentLoader(QThread):
    content_loaded = pyqtSignal(str, str, str)  # original_content, processed_content, plain_text
    error_occurred = pyqtSignal(str)
    progress_updated = pyqtSignal(int)

    def __init__(self, url, hash_mapper, encryption_enabled=True):
        super().__init__()
        self.url = url
        self.hash_mapper = hash_mapper
        self.encryption_enabled = encryption_enabled

    def run(self):
        try:
            self.progress_updated.emit(20)
            
            # Fetch webpage content
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(self.url, headers=headers, timeout=15)
            response.raise_for_status()
            
            self.progress_updated.emit(50)
            
            # Parse HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script and style elements for clean display
            for element in soup(["script", "style", "meta", "link", "noscript"]):
                element.decompose()
            
            self.progress_updated.emit(70)
            
            # Extract text content
            plain_text = soup.get_text()
            
            # Clean up text
            lines = (line.strip() for line in plain_text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            clean_text = '\n'.join(chunk for chunk in chunks if chunk)
            
            # Process content
            original_html = str(soup)
            
            if self.encryption_enabled:
                processed_html, processed_text = self.encrypt_content(soup, clean_text)
            else:
                processed_html = original_html
                processed_text = clean_text
            
            self.progress_updated.emit(100)
            self.content_loaded.emit(original_html, processed_html, processed_text)
            
        except Exception as e:
            self.error_occurred.emit(f"Error loading content: {str(e)}")

    def encrypt_content(self, soup, plain_text):
        """Encrypt words in content while preserving structure."""
        # Extract all words from text
        words = re.findall(r'\b[a-zA-Z]+\b', plain_text.lower())
        
        # Get encryption mapping
        encryption_mapping = self.hash_mapper.get_encryption_mapping(words)
        
        # Create processed HTML
        processed_soup = BeautifulSoup(str(soup), 'html.parser')
        
        # Process all text nodes
        for text_node in processed_soup.find_all(text=True):
            if text_node.parent and text_node.parent.name not in ['script', 'style', 'meta', 'link']:
                encrypted_text = self.encrypt_text_content(text_node.string, encryption_mapping)
                text_node.replace_with(encrypted_text)
        
        # Process plain text
        processed_text = self.encrypt_text_content(plain_text, encryption_mapping)
        
        return str(processed_soup), processed_text

    def encrypt_text_content(self, text, encryption_mapping):
        """Encrypt individual text content using the mapping."""
        if not text or not text.strip():
            return text
        
        def replace_word(match):
            word = match.group(0)
            word_lower = word.lower()
            if word_lower in encryption_mapping:
                encrypted = encryption_mapping[word_lower]
                # Preserve original case
                if word.isupper():
                    return encrypted.upper()
                elif word.istitle():
                    return encrypted.capitalize()
                else:
                    return encrypted
            return word
        
        # Replace words while preserving punctuation and spacing
        encrypted_text = re.sub(r'\b[a-zA-Z]+\b', replace_word, text)
        return encrypted_text

class CustomTextBrowser(QTextBrowser):
    """Custom text browser with link handling."""
    
    link_clicked = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(False)
        self.anchorClicked.connect(self.handle_link_click)
    
    def handle_link_click(self, url):
        """Handle link clicks."""
        self.link_clicked.emit(url.toString())

class HashMapperBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.hash_mapper = HashMapper(table_size=50000)
        self.encryption_enabled = True
        self.current_url = ""
        self.encryption_stats = {}
        
        self.init_ui()
        self.load_default_dictionary()
        self.apply_dark_theme()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Hash Mapper Web Browser - Word Encryption Engine")
        self.setGeometry(100, 100, 1400, 900)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel for controls
        left_panel = self.create_control_panel()
        splitter.addWidget(left_panel)
        
        # Right panel for content display
        right_panel = self.create_content_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setStretchFactor(0, 0)  # Control panel fixed
        splitter.setStretchFactor(1, 1)  # Content panel expandable
        splitter.setSizes([350, 1050])
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        self.status_bar.showMessage("Ready - Hash Mapper Browser")

    def create_control_panel(self):
        """Create the left control panel."""
        panel = QWidget()
        panel.setFixedWidth(350)
        panel.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        layout = QVBoxLayout(panel)
        
        # URL input section
        url_group = QGroupBox("🌐 Navigation")
        url_layout = QVBoxLayout(url_group)
        
        url_input_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL (e.g., wikipedia.org)...")
        self.url_input.returnPressed.connect(self.load_url)
        self.url_input.setStyleSheet("padding: 8px; border-radius: 4px; border: 2px solid #444;")
        
        self.load_button = QPushButton("🔍 Load")
        self.load_button.clicked.connect(self.load_url)
        self.load_button.setStyleSheet("padding: 8px 16px; font-weight: bold;")
        
        url_input_layout.addWidget(self.url_input)
        url_input_layout.addWidget(self.load_button)
        url_layout.addLayout(url_input_layout)
        
        # Quick access buttons
        quick_access_layout = QHBoxLayout()
        
        self.wiki_button = QPushButton("📚 Wiki")
        self.news_button = QPushButton("📰 News")
        self.demo_button = QPushButton("🧪 Demo")
        
        self.wiki_button.clicked.connect(lambda: self.load_quick_url("https://en.wikipedia.org/wiki/Cryptography"))
        self.news_button.clicked.connect(lambda: self.load_quick_url("https://www.bbc.com/news"))
        self.demo_button.clicked.connect(self.load_demo_content)
        
        for btn in [self.wiki_button, self.news_button, self.demo_button]:
            btn.setStyleSheet("padding: 5px; margin: 2px;")
        
        quick_access_layout.addWidget(self.wiki_button)
        quick_access_layout.addWidget(self.news_button)
        quick_access_layout.addWidget(self.demo_button)
        url_layout.addLayout(quick_access_layout)
        
        layout.addWidget(url_group)
        
        # Hash settings section
        hash_group = QGroupBox("⚙️ Hash Settings")
        hash_layout = QGridLayout(hash_group)
        
        # Table size
        hash_layout.addWidget(QLabel("Table Size:"), 0, 0)
        self.table_size_spin = QSpinBox()
        self.table_size_spin.setRange(1000, 1000000)
        self.table_size_spin.setValue(50000)
        self.table_size_spin.setSingleStep(1000)
        self.table_size_spin.valueChanged.connect(self.update_hash_settings)
        hash_layout.addWidget(self.table_size_spin, 0, 1)
        
        # Target word
        hash_layout.addWidget(QLabel("Target Word:"), 1, 0)
        self.target_word_input = QLineEdit("hello")
        self.target_word_input.textChanged.connect(self.update_statistics)
        hash_layout.addWidget(self.target_word_input, 1, 1)
        
        # Encryption toggle
        self.encryption_checkbox = QCheckBox("🔐 Enable Word Encryption")
        self.encryption_checkbox.setChecked(True)
        self.encryption_checkbox.toggled.connect(self.toggle_encryption)
        hash_layout.addWidget(self.encryption_checkbox, 2, 0, 1, 2)
        
        # Update button
        self.update_settings_button = QPushButton("🔄 Update Settings")
        self.update_settings_button.clicked.connect(self.update_hash_settings)
        self.update_settings_button.setStyleSheet("padding: 8px; font-weight: bold; background-color: #0d7377;")
        hash_layout.addWidget(self.update_settings_button, 3, 0, 1, 2)
        
        layout.addWidget(hash_group)
        
        # Dictionary section
        dict_group = QGroupBox("📖 Dictionary Management")
        dict_layout = QVBoxLayout(dict_group)
        
        # Dictionary controls
        dict_controls = QHBoxLayout()
        
        self.load_dict_button = QPushButton("📁 Load")
        self.save_dict_button = QPushButton("💾 Save")
        self.clear_dict_button = QPushButton("🗑️ Clear")
        
        self.load_dict_button.clicked.connect(self.load_dictionary_file)
        self.save_dict_button.clicked.connect(self.save_dictionary_file)
        self.clear_dict_button.clicked.connect(self.clear_dictionary)
        
        for btn in [self.load_dict_button, self.save_dict_button, self.clear_dict_button]:
            btn.setStyleSheet("padding: 5px 10px; margin: 1px;")
        
        dict_controls.addWidget(self.load_dict_button)
        dict_controls.addWidget(self.save_dict_button)
        dict_controls.addWidget(self.clear_dict_button)
        dict_layout.addLayout(dict_controls)
        
        # Dictionary text area
        self.dictionary_text = QTextEdit()
        self.dictionary_text.setMaximumHeight(180)
        self.dictionary_text.setStyleSheet("border: 2px solid #444; border-radius: 4px;")
        dict_layout.addWidget(self.dictionary_text)
        
        layout.addWidget(dict_group)
        
        # Statistics section
        stats_group = QGroupBox("📊 Encryption Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_label = QLabel("No content loaded")
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet("padding: 10px; background-color: rgba(0,0,0,0.2); border-radius: 4px;")
        stats_layout.addWidget(self.stats_label)
        
        # Encryption mapping display
        self.mapping_text = QTextEdit()
        self.mapping_text.setMaximumHeight(120)
        self.mapping_text.setReadOnly(True)
        self.mapping_text.setPlaceholderText("Encryption mappings will appear here...")
        self.mapping_text.setStyleSheet("font-family: 'Courier New', monospace; font-size: 11px;")
        stats_layout.addWidget(self.mapping_text)
        
        layout.addWidget(stats_group)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        return panel

    def create_content_panel(self):
        """Create the right content display panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Tab widget for different views
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #555;
                border-radius: 5px;
            }
            QTabBar::tab {
                padding: 8px 16px;
                margin: 2px;
                border-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0d7377;
                font-weight: bold;
            }
        """)
        
        # Encrypted web view tab
        self.web_view = CustomTextBrowser()
        self.web_view.link_clicked.connect(self.handle_link_click)
        self.web_view.setStyleSheet("background-color: white; color: black; padding: 10px;")
        self.tab_widget.addTab(self.web_view, "🔐 Encrypted View")
        
        # Original content tab
        self.original_text = QTextEdit()
        self.original_text.setReadOnly(True)
        self.original_text.setStyleSheet("font-family: 'Courier New', monospace; background-color: #f8f8f8; color: black;")
        self.tab_widget.addTab(self.original_text, "📄 Original HTML")
        
        # Processed content tab
        self.processed_text = QTextEdit()
        self.processed_text.setReadOnly(True)
        self.processed_text.setStyleSheet("font-family: 'Courier New', monospace; background-color: #f0f8f0; color: black;")
        self.tab_widget.addTab(self.processed_text, "🔧 Processed HTML")
        
        layout.addWidget(self.tab_widget)
        
        return panel

    def apply_dark_theme(self):
        """Apply a modern dark theme to the application."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QPushButton {
                background-color: #404040;
                border: 1px solid #555;
                padding: 6px 12px;
                border-radius: 4px;
                color: white;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border: 1px solid #777;
            }
            QPushButton:pressed {
                background-color: #333;
            }
            QLineEdit {
                background-color: #333;
                border: 2px solid #555;
                padding: 6px;
                border-radius: 4px;
                color: white;
            }
            QLineEdit:focus {
                border: 2px solid #0d7377;
            }
            QTextEdit {
                background-color: #333;
                border: 2px solid #555;
                color: white;
                border-radius: 4px;
            }
            QSpinBox {
                background-color: #333;
                border: 2px solid #555;
                padding: 4px;
                border-radius: 4px;
                color: white;
            }
            QCheckBox {
                color: white;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 2px solid #555;
                background-color: #333;
            }
            QCheckBox::indicator:checked {
                background-color: #0d7377;
                border: 2px solid #0d7377;
            }
            QLabel {
                color: white;
            }
            QStatusBar {
                background-color: #333;
                border-top: 1px solid #555;
                color: white;
            }
        """)

    def load_default_dictionary(self):
        """Load a comprehensive default dictionary."""
        default_words = [
            # Common words
            "the", "be", "to", "of", "and", "a", "in", "that", "have", "it", "for", "not", "on", "with", "he",
            "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
            "or", "an", "will", "my", "one", "all", "would", "there", "their", "what", "so", "up", "out",
            "if", "about", "who", "get", "which", "go", "me", "when", "make", "can", "like", "time", "no",
            "just", "him", "know", "take", "people", "into", "year", "your", "good", "some", "could", "them",
            "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", "also",
            "back", "after", "use", "two", "how", "our", "work", "first", "well", "way", "even", "new",
            "want", "because", "any", "these", "give", "day", "most", "us", "is", "was", "are", "been",
            "has", "had", "said", "each", "which", "time", "will", "about", "if", "up", "out", "many",
            "then", "them", "these", "so", "some", "her", "would", "make", "like", "into", "him", "two",
            "more", "go", "no", "way", "could", "my", "than", "first", "been", "call", "who", "oil", "sit",
            "now", "find", "long", "down", "day", "did", "get", "come", "made", "may", "part", "over",
            "new", "sound", "take", "only", "little", "work", "know", "place", "year", "live", "me",
            "back", "give", "most", "very", "after", "thing", "our", "name", "good", "sentence", "man",
            "think", "say", "great", "where", "help", "through", "much", "before", "line", "right", "too",
            "mean", "old", "any", "same", "tell", "boy", "follow", "came", "want", "show", "also", "around",
            "form", "three", "small", "set", "put", "end", "why", "again", "turn", "here", "off", "went",
            "number", "great", "tell", "men", "say", "small", "every", "found", "still", "between",
            "should", "home", "big", "give", "air", "line", "set", "own", "under", "read", "last",
            "never", "us", "left", "end", "along", "while", "might", "next", "sound", "below", "saw",
            "something", "thought", "both", "few", "those", "always", "show", "large", "often", "together",
            "asked", "house", "world", "going", "want", "school", "important", "until", "form", "food",
            "keep", "children", "feet", "land", "side", "without", "boy", "once", "animal", "life",
            "enough", "took", "sometimes", "four", "head", "above", "kind", "began", "almost", "live",
            "page", "got", "earth", "need", "far", "hand", "high", "year", "mother", "light", "country",
            "father", "let", "night", "picture", "being", "study", "second", "book", "carry", "science",
            "eat", "room", "friend", "began", "idea", "fish", "mountain", "north", "once", "base", "hear",
            "horse", "cut", "sure", "watch", "color", "face", "wood", "main", "open", "seem", "together",
            "next", "white", "children", "begin", "got", "walk", "example", "paper", "group", "always",
            "music", "those", "both", "mark", "often", "letter", "until", "mile", "river", "car", "feet",
            "care", "second", "enough", "plain", "girl", "usual", "young", "ready", "above", "ever", "red",
            "list", "though", "feel", "talk", "bird", "soon", "body", "dog", "family", "direct", "leave",
            "song", "measure", "door", "black", "short", "class", "wind", "question", "happen", "complete",
            "ship", "area", "half", "rock", "order", "fire", "south", "problem", "piece", "told", "knew",
            "pass", "since", "top", "whole", "king", "space", "heard", "best", "hour", "better", "during",
            "hundred", "five", "remember", "step", "early", "hold", "west", "ground", "interest", "reach",
            "fast", "verb", "sing", "listen", "six", "table", "travel", "less", "morning", "ten", "simple",
            "several", "toward", "war", "lay", "against", "pattern", "slow", "center", "love", "person",
            "money", "serve", "appear", "road", "map", "rain", "rule", "govern", "pull", "cold", "notice",
            "voice", "unit", "power", "town", "fine", "certain", "fly", "fall", "lead", "cry", "dark",
            "machine", "note", "wait", "plan", "figure", "star", "box", "noun", "field", "rest", "correct",
            "able", "pound", "done", "beauty", "drive", "stood", "contain", "front", "teach", "week",
            "final", "gave", "green", "quick", "develop", "ocean", "warm", "free", "minute", "strong",
            "special", "mind", "behind", "clear", "tail", "produce", "fact", "street", "inch", "multiply",
            "nothing", "course", "stay", "wheel", "full", "force", "blue", "object", "decide", "surface",
            "deep", "moon", "island", "foot", "system", "busy", "test", "record", "boat", "common", "gold",
            "possible", "plane", "dry", "wonder", "laugh", "thousands", "ago", "ran", "check", "game",
            "shape", "hot", "miss", "brought", "heat", "snow", "tire", "bring", "yes", "distant", "fill",
            "east", "paint", "language", "among", "grand", "ball", "yet", "wave", "drop", "heart", "am",
            "present", "heavy", "dance", "engine", "position", "arm", "wide", "sail", "material", "size",
            "vary", "settle", "speak", "weight", "general", "ice", "matter", "circle", "pair", "include",
            "divide", "syllable", "felt", "perhaps", "pick", "sudden", "count", "square", "reason", "length",
            "represent", "art", "subject", "region", "energy", "hunt", "probable", "bed", "brother", "egg",
            "ride", "cell", "believe", "fraction", "forest", "sit", "race", "window", "store", "summer",
            "train", "sleep", "prove", "lone", "leg", "exercise", "wall", "catch", "mount", "wish", "sky",
            "board", "joy", "winter", "sat", "written", "wild", "instrument", "kept", "glass", "grass",
            "cow", "job", "edge", "sign", "visit", "past", "soft", "fun", "bright", "gas", "weather",
            "month", "million", "bear", "finish", "happy", "hope", "flower", "clothe", "strange", "gone",
            "jump", "baby", "eight", "village", "meet", "root", "buy", "raise", "solve", "metal", "whether",
            "push", "seven", "paragraph", "third", "shall", "held", "hair", "describe", "cook", "floor",
            "either", "result", "burn", "hill", "safe", "cat", "century", "consider", "type", "law", "bit",
            "coast", "copy", "phrase", "silent", "tall", "sand", "soil", "roll", "temperature", "finger",
            "industry", "value", "fight", "lie", "beat", "excite", "natural", "view", "sense", "ear", "else",
            "quite", "broke", "case", "middle", "kill", "son", "lake", "moment", "scale", "loud", "spring",
            "observe", "child", "straight", "consonant", "nation", "dictionary", "milk", "speed", "method",
            "organ", "pay", "age", "section", "dress", "cloud", "surprise", "quiet", "stone", "tiny", "climb",
            "bad", "oil", "blood", "touch", "grew", "cent", "mix", "team", "wire", "cost", "lost", "brown",
            "wear", "garden", "equal", "sent", "choose", "fell", "fit", "flow", "fair", "bank", "collect",
            "save", "control", "decimal", "gentle", "woman", "captain", "practice", "separate", "difficult",
            "doctor", "please", "protect", "noon", "whose", "locate", "ring", "character", "insect", "caught",
            "period", "indicate", "radio", "spoke", "atom", "human", "history", "effect", "electric", "expect",
            "crop", "modern", "element", "hit", "student", "corner", "party", "supply", "bone", "rail", "imagine",
            "provide", "agree", "thus", "capital", "chair", "danger", "fruit", "rich", "thick", "soldier", "process",
            "operate", "guess", "necessary", "sharp", "wing", "create", "neighbor", "wash", "bat", "rather", "crowd",
            "corn", "compare", "poem", "string", "bell", "depend", "meat", "rub", "tube", "famous", "dollar", "stream",
            "fear", "sight", "thin", "triangle", "planet", "hurry", "chief", "colony", "clock", "mine", "tie", "enter",
            "major", "fresh", "search", "send", "yellow", "gun", "allow", "print", "dead", "spot", "desert", "suit",
            "current", "lift", "rose", "continue", "block", "chart", "hat", "sell", "success", "company", "subtract",
            "event", "particular", "deal", "swim", "term", "opposite", "wife", "shoe", "shoulder", "spread", "arrange",
            "camp", "invent", "cotton", "born", "determine", "quart", "nine", "truck", "noise", "level", "chance",
            "gather", "shop", "stretch", "throw", "shine", "property", "column", "molecule", "select", "wrong", "gray",
            "repeat", "require", "broad", "prepare", "salt", "nose", "plural", "anger", "claim", "continent", "oxygen",
            "sugar", "death", "pretty", "skill", "women", "season", "solution", "magnet", "silver", "thank", "branch",
            "match", "suffix", "especially", "fig", "afraid", "huge", "sister", "steel", "discuss", "forward", "similar",
            "guide", "experience", "score", "apple", "bought", "led", "pitch", "coat", "mass", "card", "band", "rope",
            "slip", "win", "dream", "evening", "condition", "feed", "tool", "total", "basic", "smell", "valley", "nor",
            "double", "seat", "arrive", "master", "track", "parent", "shore", "division", "sheet", "substance", "favor",
            "connect", "post", "spend", "chord", "fat", "glad", "original", "share", "station", "dad", "bread", "charge",
            "proper", "bar", "offer", "segment", "slave", "duck", "instant", "market", "degree", "populate", "chick",
            "dear", "enemy", "reply", "drink", "occur", "support", "speech", "nature", "range", "steam", "motion",
            "path", "liquid", "log", "meant", "quotient", "teeth", "shell", "neck"
        ]
        
        self.dictionary_text.setPlainText(' '.join(default_words))
        self.update_hash_settings()

    def update_hash_settings(self):
        """Update the hash mapper with current settings."""
        try:
            table_size = self.table_size_spin.value()
            self.hash_mapper = HashMapper(table_size=table_size)
            
            # Load dictionary words
            dictionary_text = self.dictionary_text.toPlainText()
            words = dictionary_text.split()
            
            self.hash_mapper.insert_words(words)
            
            self.status_bar.showMessage(f"Hash mapper updated: Table size {table_size:,}, Dictionary: {len(words)} words")
            
            # Update statistics
            self.update_statistics()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to update hash settings: {str(e)}")

    def toggle_encryption(self, enabled):
        """Toggle word encryption on/off."""
        self.encryption_enabled = enabled
        if self.current_url:
            self.load_url()  # Reload current page with new setting

    def load_quick_url(self, url):
        """Load a predefined URL."""
        self.url_input.setText(url)
        self.load_url()

    def load_demo_content(self):
        """Load demo content for testing."""
        demo_html = """
        <html>
        <head><title>Hash Mapper Demo</title></head>
        <body>
            <h1>Welcome to Hash Mapper Browser</h1>
            <p>This is a demonstration of word encryption using hash mapping algorithms.</p>
            <h2>How it works:</h2>
            <ul>
                <li>Each word in the dictionary is mapped to a hash table position</li>
                <li>Words are encrypted by finding alternative words using hash probing</li>
                <li>The encryption preserves sentence structure and meaning context</li>
            </ul>
            <p>Try entering different words in the target word field to see how they encrypt!</p>
            <p>Common words like "the", "and", "is", "are" will be replaced with their encrypted equivalents.</p>
            <h3>Features:</h3>
            <p>The browser supports real webpage loading and encryption. You can visit any website 
            and see how the words are transformed according to your dictionary settings.</p>
            <p>Adjust the table size for different encryption patterns. Larger tables provide more 
            varied word mappings but use more memory.</p>
        </body>
        </html>
        """
        
        # Process demo content
        soup = BeautifulSoup(demo_html, 'html.parser')
        plain_text = soup.get_text()
        
        if self.encryption_enabled:
            words = re.findall(r'\b[a-zA-Z]+\b', plain_text.lower())
            encryption_mapping = self.hash_mapper.get_encryption_mapping(words)
            
            # Encrypt the HTML content
            for text_node in soup.find_all(text=True):
                if text_node.parent and text_node.parent.name not in ['script', 'style']:
                    encrypted_text = self.encrypt_text_content(text_node.string, encryption_mapping)
                    text_node.replace_with(encrypted_text)
            
            processed_html = str(soup)
            self.encryption_stats = encryption_mapping
        else:
            processed_html = demo_html
            self.encryption_stats = {}
        
        # Update displays
        self.original_text.setPlainText(demo_html)
        self.processed_text.setPlainText(processed_html)
        self.web_view.setHtml(processed_html)
        
        self.current_url = "demo://hash-mapper-demo"
        self.url_input.setText("Demo Content")
        self.status_bar.showMessage("Demo content loaded")
        self.update_statistics()

    def encrypt_text_content(self, text, encryption_mapping):
        """Encrypt individual text content using the mapping."""
        if not text or not text.strip():
            return text
        
        def replace_word(match):
            word = match.group(0)
            word_lower = word.lower()
            if word_lower in encryption_mapping:
                encrypted = encryption_mapping[word_lower]
                # Preserve original case
                if word.isupper():
                    return encrypted.upper()
                elif word.istitle():
                    return encrypted.capitalize()
                else:
                    return encrypted
            return word
        
        # Replace words while preserving punctuation and spacing
        encrypted_text = re.sub(r'\b[a-zA-Z]+\b', replace_word, text)
        return encrypted_text

    def load_url(self):
        """Load content from the URL."""
        url = self.url_input.text().strip()
        if not url:
            return
        
        if url == "Demo Content":
            self.load_demo_content()
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_input.setText(url)
        
        self.current_url = url
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Start content loading thread
        self.content_loader = WebContentLoader(url, self.hash_mapper, self.encryption_enabled)
        self.content_loader.content_loaded.connect(self.on_content_loaded)
        self.content_loader.error_occurred.connect(self.on_content_error)
        self.content_loader.progress_updated.connect(self.progress_bar.setValue)
        self.content_loader.start()
        
        self.status_bar.showMessage(f"Loading: {url}")

    def handle_link_click(self, url):
        """Handle link clicks in the text browser."""
        if url.startswith(('http://', 'https://')):
            self.url_input.setText(url)
            self.load_url()
        else:
            QDesktopServices.openUrl(QUrl(url))

    def on_content_loaded(self, original_content, processed_content, plain_text):
        """Handle loaded content."""
        self.progress_bar.setVisible(False)
        
        # Limit content size for performance
        max_size = 100000
        
        # Update displays
        self.original_text.setPlainText(original_content[:max_size])
        self.processed_text.setPlainText(processed_content[:max_size])
        
        # Load processed content in web view with enhanced styling
        styled_html = f"""
        <html>
        <head>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    line-height: 1.6; 
                    margin: 20px; 
                    background-color: #f9f9f9;
                }}
                h1, h2, h3 {{ 
                    color: #333; 
                    border-bottom: 2px solid #0d7377;
                    padding-bottom: 5px;
                }}
                p {{ 
                    margin: 10px 0; 
                }}
                a {{ 
                    color: #0d7377; 
                    text-decoration: none; 
                }}
                a:hover {{ 
                    text-decoration: underline; 
                }}
                .encrypted-word {{
                    background-color: #e8f5f5;
                    padding: 1px 3px;
                    border-radius: 3px;
                    border: 1px solid #c0d9d9;
                }}
            </style>
        </head>
        <body>
        {processed_content}
        </body>
        </html>
        """
        
        self.web_view.setHtml(styled_html)
        
        # Extract encryption stats
        if self.encryption_enabled:
            words = re.findall(r'\b[a-zA-Z]+\b', plain_text.lower())
            self.encryption_stats = self.hash_mapper.get_encryption_mapping(words)
        else:
            self.encryption_stats = {}
        
        self.status_bar.showMessage(f"Content loaded and processed - {len(self.encryption_stats)} words encrypted")
        self.update_statistics()

    def on_content_error(self, error_message):
        """Handle content loading errors."""
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage(f"Error: {error_message}")
        QMessageBox.warning(self, "Loading Error", error_message)

    def update_statistics(self):
        """Update the statistics display."""
        try:
            if hasattr(self, 'hash_mapper'):
                filled_slots = sum(1 for slot in self.hash_mapper.table if slot is not None)
                total_slots = self.hash_mapper.table_size
                load_factor = (filled_slots / total_slots) * 100 if total_slots > 0 else 0
                
                target_word = self.target_word_input.text().lower()
                encrypted_target = self.hash_mapper.find_encrypted_word(target_word) if target_word else None
                
                stats_text = f"""📊 Hash Table Statistics:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Table Size: {total_slots:,}
Filled Slots: {filled_slots:,}
Load Factor: {load_factor:.2f}%
Total Words: {len(self.hash_mapper.word_to_index):,}

🎯 Target Word Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Input: "{target_word}"
Output: "{encrypted_target or 'Not found'}"

🔐 Current Page Encryption:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Words Encrypted: {len(self.encryption_stats):,}
Status: {'✅ Enabled' if self.encryption_enabled else '❌ Disabled'}"""
                
                self.stats_label.setText(stats_text)
                
                # Update encryption mapping display
                if self.encryption_stats:
                    mapping_text = "Recent Word Mappings:\n" + "="*30 + "\n"
                    # Show first 15 mappings
                    for i, (original, encrypted) in enumerate(list(self.encryption_stats.items())[:15]):
                        mapping_text += f"{original:12} → {encrypted}\n"
                    
                    if len(self.encryption_stats) > 15:
                        mapping_text += f"\n... and {len(self.encryption_stats) - 15} more mappings"
                    
                    self.mapping_text.setPlainText(mapping_text)
                else:
                    self.mapping_text.setPlainText("No encryption mappings available.\nLoad a webpage to see word transformations.")
                    
        except Exception as e:
            self.stats_label.setText(f"Statistics error: {str(e)}")

    def load_dictionary_file(self):
        """Load dictionary from a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Dictionary", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.dictionary_text.setPlainText(content)
                self.update_hash_settings()
                self.status_bar.showMessage(f"Dictionary loaded from: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load dictionary: {str(e)}")

    def save_dictionary_file(self):
        """Save dictionary to a file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Dictionary", "hash_dictionary.txt", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.dictionary_text.toPlainText())
                self.status_bar.showMessage(f"Dictionary saved to: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save dictionary: {str(e)}")

    def clear_dictionary(self):
        """Clear the dictionary."""
        reply = QMessageBox.question(
            self, "Clear Dictionary", 
            "Are you sure you want to clear the dictionary?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.dictionary_text.clear()
            self.update_hash_settings()
            self.status_bar.showMessage("Dictionary cleared")

def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("Hash Mapper Web Browser")
    app.setOrganizationName("HashMapper")
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the browser
    browser = HashMapperBrowser()
    browser.show()
    
    # Load demo content on startup
    QTimer.singleShot(1000, browser.load_demo_content)
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()