class ThemeManager:
    THEMES = {
        "Dark Mode": {
            "bg_dark": "#0F172A",
            "bg_card": "#1E293B",
            "bg_hover": "#334155",
            "text_main": "#F8FAFC",
            "text_sub": "#94A3B8",
            "accent": "#38BDF8",
            "accent_hover": "#0284C7",
            "border": "#334155",
            "success": "#22C55E",
            "warning": "#F59E0B",
            "danger": "#EF4444",
            "table_alt": "#162032"
        },
        "Light Mode": {
            "bg_dark": "#F1F5F9",
            "bg_card": "#FFFFFF",
            "bg_hover": "#E2E8F0",
            "text_main": "#0F172A",
            "text_sub": "#64748B",
            "accent": "#2563EB",
            "accent_hover": "#1D4ED8",
            "border": "#CBD5E1",
            "success": "#16A34A",
            "warning": "#D97706",
            "danger": "#DC2626",
            "table_alt": "#F8FAFC"
        },
        "Blue Cyber": {
            "bg_dark": "#0B132B",
            "bg_card": "#1C2541",
            "bg_hover": "#3A506B",
            "text_main": "#E0FBFC",
            "text_sub": "#8D99AE",
            "accent": "#00F5D4",
            "accent_hover": "#00BBF9",
            "border": "#3A506B",
            "success": "#00F5D4",
            "warning": "#FFB703",
            "danger": "#FF0054",
            "table_alt": "#151D35"
        },
        "Green Hacker": {
            "bg_dark": "#0A0F0D",
            "bg_card": "#121A16",
            "bg_hover": "#1E2B24",
            "text_main": "#00FF66",
            "text_sub": "#70A985",
            "accent": "#00FF66",
            "accent_hover": "#00CC52",
            "border": "#1E2B24",
            "success": "#00FF66",
            "warning": "#FFD166",
            "danger": "#FF4757",
            "table_alt": "#0E1412"
        }
    }

    @classmethod
    def get_qss(cls, theme_name: str) -> str:
        t = cls.THEMES.get(theme_name, cls.THEMES["Dark Mode"])
        return f"""
        QMainWindow, QDialog {{
            background-color: {t["bg_dark"]};
            color: {t["text_main"]};
            font-family: 'Segoe UI', Roboto, Helvetica, sans-serif;
        }}

        QWidget {{
            color: {t["text_main"]};
            font-size: 13px;
        }}

        #SidebarFrame {{
            background-color: {t["bg_card"]};
            border-right: 1px solid {t["border"]};
        }}

        #SidebarHeader {{
            padding: 15px;
            font-size: 18px;
            font-weight: bold;
            color: {t["accent"]};
        }}

        QPushButton.NavButton {{
            background-color: transparent;
            color: {t["text_sub"]};
            border: none;
            border-radius: 6px;
            padding: 10px 16px;
            text-align: left;
            font-size: 14px;
            font-weight: 500;
        }}

        QPushButton.NavButton:hover {{
            background-color: {t["bg_hover"]};
            color: {t["text_main"]};
        }}

        QPushButton.NavButton:checked {{
            background-color: {t["accent"]};
            color: {t["bg_dark"]};
            font-weight: bold;
        }}

        #TopHeaderBar {{
            background-color: {t["bg_card"]};
            border-bottom: 1px solid {t["border"]};
            padding: 8px 16px;
        }}

        QFrame.StatCard {{
            background-color: {t["bg_card"]};
            border: 1px solid {t["border"]};
            border-radius: 10px;
            padding: 14px;
        }}

        QFrame.StatCard:hover {{
            border: 1px solid {t["accent"]};
        }}

        QLabel.StatValue {{
            font-size: 26px;
            font-weight: bold;
            color: {t["accent"]};
        }}

        QLabel.StatTitle {{
            font-size: 12px;
            color: {t["text_sub"]};
            text-transform: uppercase;
        }}

        QTableWidget {{
            background-color: {t["bg_card"]};
            alternate-background-color: {t["table_alt"]};
            gridline-color: {t["border"]};
            border: 1px solid {t["border"]};
            border-radius: 8px;
            selection-background-color: {t["accent"]};
            selection-color: {t["bg_dark"]};
        }}

        QHeaderView::section {{
            background-color: {t["bg_hover"]};
            color: {t["text_main"]};
            padding: 8px;
            font-weight: bold;
            border: none;
            border-bottom: 2px solid {t["border"]};
        }}

        QLineEdit {{
            background-color: {t["bg_card"]};
            color: {t["text_main"]};
            border: 1px solid {t["border"]};
            border-radius: 6px;
            padding: 8px 12px;
        }}

        QLineEdit:focus {{
            border: 1px solid {t["accent"]};
        }}

        QComboBox {{
            background-color: {t["bg_card"]};
            color: {t["text_main"]};
            border: 1px solid {t["border"]};
            border-radius: 6px;
            padding: 6px 12px;
        }}

        QPushButton.PrimaryButton {{
            background-color: {t["accent"]};
            color: {t["bg_dark"]};
            font-weight: bold;
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
        }}

        QPushButton.PrimaryButton:hover {{
            background-color: {t["accent_hover"]};
        }}

        QPushButton.SecondaryButton {{
            background-color: {t["bg_hover"]};
            color: {t["text_main"]};
            border: 1px solid {t["border"]};
            border-radius: 6px;
            padding: 8px 16px;
        }}

        QPushButton.SecondaryButton:hover {{
            border: 1px solid {t["accent"]};
        }}

        QProgressBar {{
            border: 1px solid {t["border"]};
            border-radius: 4px;
            text-align: center;
            background-color: {t["bg_card"]};
            color: {t["text_main"]};
        }}

        QProgressBar::chunk {{
            background-color: {t["accent"]};
            border-radius: 4px;
        }}

        QTabWidget::pane {{
            border: 1px solid {t["border"]};
            border-radius: 6px;
            background-color: {t["bg_card"]};
        }}

        QTabBar::tab {{
            background-color: {t["bg_hover"]};
            color: {t["text_sub"]};
            padding: 8px 16px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 2px;
        }}

        QTabBar::tab:selected {{
            background-color: {t["accent"]};
            color: {t["bg_dark"]};
            font-weight: bold;
        }}

        QTextEdit, QPlainTextEdit {{
            background-color: {t["bg_card"]};
            color: {t["text_main"]};
            border: 1px solid {t["border"]};
            border-radius: 6px;
        }}
        """
