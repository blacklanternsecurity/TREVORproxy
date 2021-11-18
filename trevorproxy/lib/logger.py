### LOGGING ###

import sys
import logging
from pathlib import Path

### LOG TO STDOUT AND FILE ###

log_dir = Path.home() / '.trevorproxy'
log_file = log_dir / 'trevorproxy.log'
log_dir.mkdir(exist_ok=True)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
file_handler = logging.FileHandler(str(log_file))
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))

root_logger = logging.getLogger('trevorproxy')
root_logger.handlers = [console_handler, file_handler]
root_logger.setLevel(logging.DEBUG)