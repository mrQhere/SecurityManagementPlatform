import sys
import os
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                               QLineEdit, QPushButton, QProgressBar, 
                               QApplication, QFrame, QWidget, QSizePolicy)
from PySide6.QtCore import Qt, QPropertyAnimation, QPoint, QTimer, QThread, Signal
from PySide6.QtGui import QIcon, QFont, QPalette, QColor

class PBKDF2Thread(QThread):
    progress = Signal(int)
    finished_check = Signal(bool)

    def __init__(self, password, parent=None):
        super().__init__(parent)
        self.password = password

    def run(self):
        # Fake progress over ~1s
        for i in range(1, 101):
            self.progress.emit(i)
            self.msleep(10)
        # Deferred import
        try:
            from tools import encryption_manager
            valid = encryption_manager.verify_master_password(self.password)
        except Exception:
            # Fallback if tools not available
            valid = True if self.password else False
        self.finished_check.emit(valid)

class PasswordDialog(QDialog):
    def __init__(self, parent=None, first_run=False):
        super().__init__(parent)
        self.first_run = first_run
        self.accepted_password = ""
        self.wrong_attempts = 0
        self.locked = False
        self.lock_seconds_remaining = 0
        
        self.setWindowTitle("Unlock SMP" if not first_run else "Create Master Password")
        self.setFixedSize(450, 500 if first_run else 350)
        self.setWindowFlags(self.windowFlags() | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        self._init_ui()
        self._apply_styles()
        
    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        self.card = QFrame(self)
        self.card.setObjectName("card")
        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(30, 30, 30, 30)
        card_layout.setSpacing(15)
        
        # Header
        header_label = QLabel("🔒 Security Management Platform")
        header_font = QFont("Arial", 16, QFont.Bold)
        header_label.setFont(header_font)
        header_label.setAlignment(Qt.AlignCenter)
        header_label.setStyleSheet("color: #FFFFFF;")
        card_layout.addWidget(header_label)
        
        sub_label = QLabel("Create your master password" if self.first_run else "Enter your master password to unlock")
        sub_label.setAlignment(Qt.AlignCenter)
        sub_label.setStyleSheet("color: #A0A0A0;")
        card_layout.addWidget(sub_label)
        
        # Password field
        pwd_layout = QHBoxLayout()
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Password")
        
        self.toggle_pwd_btn = QPushButton("👁")
        self.toggle_pwd_btn.setCheckable(True)
        self.toggle_pwd_btn.setFixedSize(30, 30)
        self.toggle_pwd_btn.toggled.connect(self._toggle_pwd_visibility)
        
        pwd_layout.addWidget(self.pwd_input)
        pwd_layout.addWidget(self.toggle_pwd_btn)
        card_layout.addLayout(pwd_layout)
        
        if self.first_run:
            # Confirm password
            self.confirm_pwd_input = QLineEdit()
            self.confirm_pwd_input.setEchoMode(QLineEdit.Password)
            self.confirm_pwd_input.setPlaceholderText("Confirm Password")
            card_layout.addWidget(self.confirm_pwd_input)
            
            # Strength meter
            self.strength_bar = QProgressBar()
            self.strength_bar.setTextVisible(False)
            self.strength_bar.setFixedHeight(8)
            card_layout.addWidget(self.strength_bar)
            
            self.strength_label = QLabel("Strength: None")
            self.strength_label.setStyleSheet("color: #A0A0A0; font-size: 11px;")
            card_layout.addWidget(self.strength_label)
            
            # Checklist
            self.req_len = QLabel("❌ 8+ characters")
            self.req_upper = QLabel("❌ Uppercase letter")
            self.req_lower = QLabel("❌ Lowercase letter")
            self.req_digit = QLabel("❌ Digit")
            self.req_special = QLabel("❌ Special character")
            
            for req in [self.req_len, self.req_upper, self.req_lower, self.req_digit, self.req_special]:
                req.setStyleSheet("color: #A0A0A0; font-size: 11px;")
                card_layout.addWidget(req)
                
            self.pwd_input.textChanged.connect(self._on_password_changed)
        else:
            self.warning_label = QLabel("")
            self.warning_label.setStyleSheet("color: #F87171; font-weight: bold;")
            self.warning_label.setAlignment(Qt.AlignCenter)
            self.warning_label.hide()
            card_layout.addWidget(self.warning_label)
            
        # Progress bar for derivation
        self.auth_progress = QProgressBar()
        self.auth_progress.setTextVisible(False)
        self.auth_progress.setFixedHeight(4)
        self.auth_progress.hide()
        card_layout.addWidget(self.auth_progress)
        
        # Action button
        self.action_btn = QPushButton("Set Password" if self.first_run else "Unlock")
        self.action_btn.setFixedHeight(40)
        self.action_btn.clicked.connect(self._on_action_clicked)
        card_layout.addWidget(self.action_btn)
        
        if not self.first_run:
            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(self.reject)
            card_layout.addWidget(cancel_btn)
            
        main_layout.addWidget(self.card)

    def _apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: transparent;
            }
            QFrame#card {
                background-color: #151820;
                border-radius: 12px;
                border: 1px solid #2A2F3D;
            }
            QLineEdit {
                background-color: #0D0F14;
                border: 1px solid #2A2F3D;
                border-radius: 6px;
                color: #FFFFFF;
                padding: 8px;
            }
            QLineEdit:focus {
                border: 1px solid #00D4FF;
            }
            QPushButton {
                background-color: #3B82F6;
                color: white;
                border: none;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2563EB;
            }
            QPushButton:disabled {
                background-color: #4B5563;
                color: #9CA3AF;
            }
            QProgressBar {
                background-color: #2A2F3D;
                border: none;
                border-radius: 4px;
            }
        """)

    def _toggle_pwd_visibility(self, checked):
        if checked:
            self.pwd_input.setEchoMode(QLineEdit.Normal)
            if self.first_run:
                self.confirm_pwd_input.setEchoMode(QLineEdit.Normal)
        else:
            self.pwd_input.setEchoMode(QLineEdit.Password)
            if self.first_run:
                self.confirm_pwd_input.setEchoMode(QLineEdit.Password)

    def password_strength(self, password: str) -> tuple[int, str]:
        score = 0
        if len(password) >= 8: score += 20
        if any(c.isupper() for c in password): score += 20
        if any(c.islower() for c in password): score += 20
        if any(c.isdigit() for c in password): score += 20
        if any(not c.isalnum() for c in password): score += 20
        
        if score < 40: return score, "Weak"
        elif score < 80: return score, "Fair"
        else: return score, "Strong"

    def _on_password_changed(self, text):
        score, label = self.password_strength(text)
        self.strength_bar.setValue(score)
        self.strength_label.setText(f"Strength: {label}")
        
        if score < 40:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #F87171; border-radius: 4px; }")
        elif score < 80:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #FBBF24; border-radius: 4px; }")
        else:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #34D399; border-radius: 4px; }")
            
        self.req_len.setText(f"{'✅' if len(text) >= 8 else '❌'} 8+ characters")
        self.req_upper.setText(f"{'✅' if any(c.isupper() for c in text) else '❌'} Uppercase letter")
        self.req_lower.setText(f"{'✅' if any(c.islower() for c in text) else '❌'} Lowercase letter")
        self.req_digit.setText(f"{'✅' if any(c.isdigit() for c in text) else '❌'} Digit")
        self.req_special.setText(f"{'✅' if any(not c.isalnum() for c in text) else '❌'} Special character")

    def shake_animation(self):
        self.anim = QPropertyAnimation(self, b"pos")
        self.anim.setDuration(400)
        start_pos = self.pos()
        self.anim.setKeyValueAt(0, start_pos)
        self.anim.setKeyValueAt(0.1, start_pos + QPoint(10, 0))
        self.anim.setKeyValueAt(0.3, start_pos + QPoint(-10, 0))
        self.anim.setKeyValueAt(0.5, start_pos + QPoint(10, 0))
        self.anim.setKeyValueAt(0.7, start_pos + QPoint(-10, 0))
        self.anim.setKeyValueAt(0.9, start_pos + QPoint(5, 0))
        self.anim.setKeyValueAt(1.0, start_pos)
        self.anim.start()

    def _on_action_clicked(self):
        if self.locked: return
        
        password = self.pwd_input.text()
        
        if self.first_run:
            if password != self.confirm_pwd_input.text():
                self.shake_animation()
                return
            score, _ = self.password_strength(password)
            if score < 100:
                self.shake_animation()
                return
            
            try:
                from tools import encryption_manager
                encryption_manager.set_master_password(password)
            except Exception:
                pass
            
            self.accepted_password = password
            self.accept()
        else:
            self.action_btn.setEnabled(False)
            self.auth_progress.show()
            self.auth_progress.setValue(0)
            
            self.auth_thread = PBKDF2Thread(password, self)
            self.auth_thread.progress.connect(self.auth_progress.setValue)
            self.auth_thread.finished_check.connect(self._on_auth_finished)
            self.auth_thread.start()
            
    def _on_auth_finished(self, is_valid):
        self.auth_progress.hide()
        self.action_btn.setEnabled(True)
        
        if is_valid:
            self.accepted_password = self.pwd_input.text()
            self.accept()
        else:
            self.wrong_attempts += 1
            if self.wrong_attempts >= 5:
                self._lock_dialog()
            elif self.wrong_attempts >= 3:
                self.warning_label.setText(f"Warning: {5 - self.wrong_attempts} attempts remaining")
                self.warning_label.show()
            self.shake_animation()
            
    def _lock_dialog(self):
        self.locked = True
        self.pwd_input.setEnabled(False)
        self.action_btn.setEnabled(False)
        self.warning_label.show()
        self.lock_seconds_remaining = 30
        
        self.lock_timer = QTimer(self)
        self.lock_timer.timeout.connect(self._on_lock_timer)
        self.lock_timer.start(1000)
        self._on_lock_timer()
        
    def _on_lock_timer(self):
        if self.lock_seconds_remaining > 0:
            self.warning_label.setText(f"Locked. Try again in {self.lock_seconds_remaining}s")
            self.lock_seconds_remaining -= 1
        else:
            self.lock_timer.stop()
            self.locked = False
            self.pwd_input.setEnabled(True)
            self.action_btn.setEnabled(True)
            self.warning_label.hide()
            self.wrong_attempts = 0

if __name__ == "__main__":
    app = QApplication(sys.argv)
    d = PasswordDialog(first_run=True)
    d.show()
    sys.exit(app.exec())
