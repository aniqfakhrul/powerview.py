import datetime

__year__ = datetime.date.today().year
__version__ = f"{__year__}.1.6"
__author__ = [
	"Aniq Fakhrul",
	"Ali Radzali"
]

BANNER = "Powerview.py v{} ({}) - by {}\n".format(__version__, __year__, ", ".join(__author__))
