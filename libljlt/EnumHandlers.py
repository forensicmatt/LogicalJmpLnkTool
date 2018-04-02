import os
import pytsk3
from libljlt.TskFileIo import TskFileIo
from libljlt.LnkHandler import LnkHandler


class FileInfo(object):
    def __init__(self, fullname, attribute):
        self.fullname = fullname
        self.filename = attribute.info.fs_file.name.name
        self.id = attribute.info.id
        self.type = attribute.info.type
        self.size = attribute.info.size
        self.attribute_name = attribute.info.name


class FileEnumerator(object):
    def __init__(self, source):
        self.source = source

    def process_files(self):
        if os.path.exists(self.source):
            if os.path.isfile(self.source):
                with open(self.source, 'rb') as fh:
                    handler = LnkHandler(
                        self.source,
                        fh
                    )
                    handler.parse()
            elif os.path.isdir(self.source):
                for root, dirs, files in os.walk(self.source):
                    for filename in files:
                        lower_filename = filename.lower()
                        if lower_filename.endswith("destinations-ms") or lower_filename.endswith(".lnk"):
                            full_path = os.path.join(root, filename)
                            with open(full_path, 'rb') as fh:
                                handler = LnkHandler(
                                    full_path,
                                    fh
                                )
                                handler.parse()
            else:
                raise (
                    Exception("{} is not a file or directory.".format(self.source))
                )
        else:
            raise(
                Exception("{} does not exist.".format(self.source))
            )


class LogicalEnumerator(object):
    """A class to process the logical volume."""
    def __init__(self, file_io, description=u""):
        """Create LogicalEnumerator

        Params:
            file_io (FileIO): I file like object representing a volume.
            temp_dir (unicode): The location to extract files to
            description (unicode): The label for this LogicalEnumerator
        """
        self.file_io = file_io
        self.description = description
        self.tsk_fs = pytsk3.FS_Info(
            self.file_io
        )

    def _iter_directory(self, tsk_dir, stack=[]):
        """Iterate a directory looking for file entries.

        Params:
            tsk_dir: TSK File as a directory
            stack: A list of path names that gives the full path
        """
        for tsk_file in tsk_dir:
            filename = tsk_file.info.name.name.decode('utf-8')

            if filename in [u".", u".."]:
                continue

            if hasattr(tsk_file.info, 'meta'):
                if hasattr(tsk_file.info.meta, 'type'):
                    is_dir = tsk_file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                else:
                    # logging.debug(u"not sure how to handle here...")
                    continue
            else:
                # logging.debug(u"not sure how to handle here...")
                continue

            if is_dir:
                stack.append(filename)
                self._iter_directory(
                    tsk_file.as_directory(), stack=stack
                )
                stack.pop()
            else:
                self._process_entry(
                    tsk_file, u"/".join(stack)
                )

    def _process_entry(self, tsk_file, full_path):
        """Process a TSK File.

        Params:
            tsk_file (TSK File): A TSK File object
            full_path (unicode): The fullpath of this file object
        """
        filename = tsk_file.info.name.name.decode('utf-8')
        if not filename:
            return

        filename_lower = filename.lower()
        if not (filename_lower.endswith("destinations-ms") or filename_lower.endswith(".lnk")):
            return

        fullname = u"/".join([full_path, filename])

        for attr in tsk_file:
            if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA:
                if attr.info.name:
                    # source_path = u":".join([fullname, attr.info.name.decode('utf-8')])
                    # Don't worry about ads...
                    continue
                else:
                    source_path = fullname

                file_info = FileInfo(
                    source_path, attr
                )

                file_io = TskFileIo(
                    tsk_file, file_info
                )

                handler = LnkHandler(
                    source_path,
                    file_io
                )
                handler.parse()

    def process_files(self, directory=u"/"):
        """Entry into processing all files for this LogicalEnumerator.

        Params:
            directory (unicode): The starting directory to recurse. (default is root)
        """
        tsk_dir = self.tsk_fs.open_dir(directory)
        self._iter_directory(
            tsk_dir, stack=[u"."]
        )
