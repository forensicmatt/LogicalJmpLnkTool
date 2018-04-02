import re
import pytsk3
import logging
import argparse
from libljlt import EnumHandlers as Eh

logging.basicConfig(
    level=logging.DEBUG
)


def get_arguments():
    usage = '''Process jumplist or link files from a logical volume (or dir, or file). The output is in JSONL format.
    This tool requires Admin privileges to open the Logical Volume.'''

    arguments = argparse.ArgumentParser(
        description=(usage)
    )
    arguments.add_argument(
        "-s", "--source",
        dest="source",
        action="store",
        required=True,
        help=u"Logical source, path, or file."
    )

    return arguments


def main():
    arguments = get_arguments()
    options = arguments.parse_args()

    if re.match('\\\\\\\.\\\[a-zA-Z]:', options.source):
        tsk_img = pytsk3.Img_Info(
            options.source
        )

        le = Eh.LogicalEnumerator(
            tsk_img,
            description=options.source
        )
        le.process_files()
    else:
        fe = Eh.FileEnumerator(
            options.source
        )
        fe.process_files()


if __name__ == "__main__":
    main()