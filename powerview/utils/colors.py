from os import system

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKCYAN = '\033[96m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

class Gradient:
	# from https://github.com/venaxyt/fade
	@staticmethod
	def fire(text):
		system(""); faded = ""
		green = 250
		for line in text.splitlines():
			faded += (f"\033[38;2;255;{green};0m{line}\033[0m\n")
			if not green == 0:
				green -= 25
				if green < 0:
					green = 0
		return faded

	@staticmethod
	def water(text):
		system(""); faded = ""
		green = 10
		for line in text.splitlines():
			faded += (f"\033[38;2;0;{green};255m{line}\033[0m\n")
			if not green == 255:
				green += 15
				if green > 255:
					green = 255
		return faded