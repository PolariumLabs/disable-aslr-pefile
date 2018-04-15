import logging
import argparse
import argparse
import pefile
import os

g_logger = logging.getLogger(__name__)

def set_up_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    return parser.parse_args().file

def main():
    set_up_logging()
    file = parse_args()
    pe = pefile.PE(file)
    g_logger.info("DllCharacteristics: 0x%X." % pe.OPTIONAL_HEADER.DllCharacteristics)
    is_dynamic_base_enabled = bool(pe.OPTIONAL_HEADER.DllCharacteristics & pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"])
    g_logger.info("IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE: %r" % is_dynamic_base_enabled)
    
    if(is_dynamic_base_enabled):
        g_logger.info("Disabling ASLR.")
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]
        g_logger.info("ASLR Disabled.")
    else:
        g_logger.info("Enabling ASLR.")
        pe.OPTIONAL_HEADER.DllCharacteristics |= pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]
        g_logger.info("ASLR Enabled.")

    file_no_ext, ext = os.path.splitext(file)
    new_file_name = "%s_aslr_%s%s" % (file_no_ext, ["enabled", "disabled"][int(is_dynamic_base_enabled)], ext)
    g_logger.info("Saving file: %s." % new_file_name)
    pe.write(filename=new_file_name)
    pe.close()
    g_logger.info("File saved: %s." % (new_file_name))

if __name__ == '__main__':
    main()