# manage_whitelist.py

import logging
from whitelist_manager import open_whitelist_gui

def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("whitelist_manager.log"),
            logging.StreamHandler()
        ]
    )
    open_whitelist_gui()

if __name__ == "__main__":
    main()
