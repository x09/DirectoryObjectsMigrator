"""
Internationalization (i18n) support
Handles translation setup using gettext
"""
import gettext
import locale
import os
from pathlib import Path
from typing import Optional
from config import settings


class I18n:
    """Internationalization manager"""

    _instance = None
    _translator = None
    _current_language = None

    def __new__(cls):
        """Singleton pattern"""
        if cls._instance is None:
            cls._instance = super(I18n, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize i18n"""
        if self._initialized:
            return

        self._initialized = True
        self._load_language(settings.DEFAULT_LANGUAGE)

    def _find_locale_dir(self) -> Optional[Path]:
        """
        Find locale directory

        Searches in:
        1. Application locale directory (next to this file)
        2. /usr/share/locale
        3. System paths

        Returns:
            Path to locale directory or None
        """
        # Try application locale directory first
        app_locale_dir = Path(__file__).parent.parent / "locale"
        if app_locale_dir.exists():
            return app_locale_dir

        # Try system locale directories
        for locale_dir in settings.LOCALE_DIRS:
            if locale_dir.exists():
                # Check if our domain exists there
                for lang in settings.SUPPORTED_LANGUAGES:
                    mo_file = locale_dir / lang / "LC_MESSAGES" / f"{settings.TEXTDOMAIN}.mo"
                    if mo_file.exists():
                        return locale_dir

        return None

    def _load_language(self, language: str):
        """
        Load language translations

        Args:
            language: Language code (e.g., 'en', 'ru')
        """
        if language not in settings.SUPPORTED_LANGUAGES:
            language = settings.DEFAULT_LANGUAGE

        locale_dir = self._find_locale_dir()

        try:
            if locale_dir:
                # Load translations from .mo file
                self._translator = gettext.translation(
                    settings.TEXTDOMAIN,
                    localedir=str(locale_dir),
                    languages=[language],
                    fallback=True
                )
            else:
                # No translations found, use fallback (English)
                self._translator = gettext.NullTranslations()

            self._translator.install()
            self._current_language = language

        except Exception as e:
            print(f"Warning: Could not load translations for '{language}': {e}")
            # Use fallback (no translation)
            self._translator = gettext.NullTranslations()
            self._translator.install()
            self._current_language = settings.DEFAULT_LANGUAGE

    def set_language(self, language: str):
        """
        Change current language

        Args:
            language: Language code
        """
        if language != self._current_language:
            self._load_language(language)

    def get_language(self) -> str:
        """Get current language code"""
        return self._current_language or settings.DEFAULT_LANGUAGE

    def get_available_languages(self) -> list:
        """Get list of available languages"""
        return settings.SUPPORTED_LANGUAGES

    def translate(self, message: str) -> str:
        """
        Translate a message

        Args:
            message: Message to translate

        Returns:
            Translated message
        """
        if self._translator:
            return self._translator.gettext(message)
        return message

    def translate_plural(self, singular: str, plural: str, n: int) -> str:
        """
        Translate a message with plural forms

        Args:
            singular: Singular form
            plural: Plural form
            n: Count

        Returns:
            Translated message
        """
        if self._translator:
            return self._translator.ngettext(singular, plural, n)
        return singular if n == 1 else plural


# Global instance
_i18n = I18n()


# Convenience functions (mimicking gettext API)
def _(message: str) -> str:
    """Translate message (shorthand for gettext)"""
    return _i18n.translate(message)


def ngettext(singular: str, plural: str, n: int) -> str:
    """Translate with plural forms"""
    return _i18n.translate_plural(singular, plural, n)


def set_language(language: str):
    """Set current language"""
    _i18n.set_language(language)


def get_language() -> str:
    """Get current language"""
    return _i18n.get_language()


def get_available_languages() -> list:
    """Get available languages"""
    return _i18n.get_available_languages()


def detect_system_language() -> str:
    """
    Detect system language

    Returns:
        Language code (en/ru) based on system locale
    """
    try:
        # Get system locale
        system_locale, _ = locale.getdefaultlocale()

        if system_locale:
            # Extract language code (first 2 chars)
            lang_code = system_locale[:2].lower()

            if lang_code in settings.SUPPORTED_LANGUAGES:
                return lang_code

    except Exception:
        pass

    return settings.DEFAULT_LANGUAGE


if __name__ == "__main__":
    # Self-test
    print("=== I18n Test ===\n")

    print(f"Available languages: {get_available_languages()}")
    print(f"Current language: {get_language()}")
    print(f"System language: {detect_system_language()}")

    print("\n--- English ---")
    set_language('en')
    print(_("Welcome"))
    print(_("Migration completed successfully"))

    print("\n--- Russian ---")
    set_language('ru')
    print(_("Welcome"))
    print(_("Migration completed successfully"))

    print("\nNote: Translations require .mo files in locale/ directory")
