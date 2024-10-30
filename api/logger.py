import logging

log = logging.getLogger(__name__)
logging.basicConfig(
    filename="moviesapp.log",
    format="{asctime} - {levelname} - {filename} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)