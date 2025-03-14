import os
import time
from libarchive import is_archive, Entry, SeekableArchive, _libarchive
from zipfile import ZIP_STORED, ZIP_DEFLATED


def is_zipfile(filename):
    return is_archive(filename, formats=('zip',))


def sanitize_filename(filename, base_path=os.getcwd()):
    abs_path = os.path.abspath(os.path.join(base_path, filename))
    if not abs_path.startswith(os.path.abspath(base_path) + os.sep):
        raise ValueError("Invalid filename: Potential directory traversal attempt detected.")
    return os.path.basename(abs_path)  # Ensures only filename is extracted

class ZipEntry(Entry):
    def __init__(self, *args, **kwargs):
        super(ZipEntry, self).__init__(*args, **kwargs)

    def get_filename(self):
        return self.pathname

    def set_filename(self, value):
        self.pathname = value

    filename = property(get_filename, set_filename)

    def get_file_size(self):
        return self.size

    def set_file_size(self, value):
        assert isinstance(value, int), 'Please provide size as int or long.'
        self.size = value

    file_size = property(get_file_size, set_file_size)

    def get_date_time(self):
        return time.localtime(self.mtime)[0:6]

    def set_date_time(self, value):
        assert isinstance(value, tuple), 'mtime should be tuple (year, month, day, hour, minute, second).'
        assert len(value) == 6, 'mtime should be tuple (year, month, day, hour, minute, second).'
        self.mtime = time.mktime(value + (0, 0, 0))

    date_time = property(get_date_time, set_date_time)

    header_offset = Entry.header_position

    def _get_missing(self):
        raise NotImplemented()

    def _set_missing(self, value):
        raise NotImplemented()

    compress_type = property(_get_missing, _set_missing)
    comment = property(_get_missing, _set_missing)
    extra = property(_get_missing, _set_missing)
    create_system = property(_get_missing, _set_missing)
    create_version = property(_get_missing, _set_missing)
    extract_version = property(_get_missing, _set_missing)
    reserved = property(_get_missing, _set_missing)
    flag_bits = property(_get_missing, _set_missing)
    volume = property(_get_missing, _set_missing)
    internal_attr = property(_get_missing, _set_missing)
    external_attr = property(_get_missing, _set_missing)
    CRC = property(_get_missing, _set_missing)
    compress_size = property(_get_missing, _set_missing)


class ZipFile(SeekableArchive):
    def __init__(self, f, mode='r', compression=ZIP_DEFLATED, allowZip64=False, password=None,
                 encryption=None):
        self.compression = compression
        self.encryption = encryption
        super(ZipFile, self).__init__(
            f, mode=mode, format='zip', entry_class=ZipEntry, encoding='CP437', password=password
        )

    getinfo = SeekableArchive.getentry

    def set_initial_options(self):
        if self.mode == 'w' and self.compression == ZIP_STORED:
            _libarchive.archive_write_set_format_option(self._a, "zip", "compression", "store")

        if self.mode == 'w' and self.password:
            if not self.encryption:
                self.encryption = "traditional"
            _libarchive.archive_write_set_format_option(self._a, "zip", "encryption", self.encryption)

    def namelist(self):
        return list(self.iterpaths())

    def infolist(self):
        return list(self)

    def open(self, name, mode, pwd=None):
        if mode == 'r':
            if pwd:
                self.add_passphrase(pwd)
            return self.readstream(name)
        else:
            return self.writestream(name)

    def extract(self, name, path=None, pwd=None):
        if pwd:
            self.add_passphrase(pwd)
        if not path:
            path = os.getcwd()
        sanitized_name = sanitize_filename(name)
        return self.readpath(sanitized_name, os.path.join(path, sanitized_name))

    def extractall(self, path, names=None, pwd=None):
        if pwd:
            self.add_passphrase(pwd)
        if not names:
            names = self.namelist()
        if names:
            for name in names:
                sanitized_name = sanitize_filename(name, path)
                self.extract(sanitized_name, path)

    def read(self, name, pwd=None):
        if pwd:
            self.add_passphrase(pwd)
        return super(ZipFile, self).read(name)

    def writestr(self, member, data, compress_type=None):
        if compress_type != self.compression and not (compress_type is None):
            raise Exception('Cannot change compression type for individual entries.')
        return self.write(member, data)

    def setpassword(self, pwd):
        return self.set_passphrase(pwd)

    def testzip(self):
        raise NotImplemented()

    def _get_missing(self):
        raise NotImplemented()

    def _set_missing(self, value):
        raise NotImplemented()

    comment = property(_get_missing, _set_missing)
