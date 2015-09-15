import dbus

class ImageScannerClientError(dbus.DBusException):
        """ImageScanner error"""
        dbus_error_name = 'org.atomic.Exception'
