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
	BLACK = '\033[30m'
	RED = '\033[31m'
	GREEN = '\033[32m'
	YELLOW = '\033[33m'
	BLUE = '\033[34m'
	MAGENTA = '\033[35m'
	CYAN = '\033[36m'
	WHITE = '\033[37m'
	BRIGHTBLACK = '\033[90m'
	BRIGHTRED = '\033[91m'
	BRIGHTGREEN = '\033[92m'
	BRIGHTYELLOW = '\033[93m'
	BRIGHTBLUE = '\033[94m'
	BRIGHTMAGENTA = '\033[95m'
	BRIGHTCYAN = '\033[96m'
	BRIGHTWHITE = '\033[97m'
	BG_BLACK = '\033[40m'
	BG_RED = '\033[41m'
	BG_GREEN = '\033[42m'
	BG_YELLOW = '\033[43m'
	BG_BLUE = '\033[44m'
	BG_MAGENTA = '\033[45m'
	BG_CYAN = '\033[46m'
	BG_WHITE = '\033[47m'
	ITALIC = '\033[3m'
	STRIKETHROUGH = '\033[9m'
	INVERT = '\033[7m'
	GREY = '\033[2;37m'

class Gradient:
	"""
	Advanced text gradient effects for terminal output.
	"""
	
	@staticmethod
	def fire(text):
		"""Red to yellow gradient."""
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
		"""Blue to cyan gradient."""
		system(""); faded = ""
		green = 10
		for line in text.splitlines():
			faded += (f"\033[38;2;0;{green};255m{line}\033[0m\n")
			if not green == 255:
				green += 15
				if green > 255:
					green = 255
		return faded
	
	@staticmethod
	def purple(text):
		"""Purple to pink gradient."""
		system(""); faded = ""
		blue = 255
		for line in text.splitlines():
			faded += (f"\033[38;2;128;0;{blue}m{line}\033[0m\n")
			if not blue == 0:
				blue -= 25
				if blue < 0:
					blue = 0
		return faded
	
	@staticmethod
	def forest(text):
		"""Dark green to light green gradient."""
		system(""); faded = ""
		green = 100
		for line in text.splitlines():
			faded += (f"\033[38;2;0;{green};0m{line}\033[0m\n")
			if not green == 255:
				green += 15
				if green > 255:
					green = 255
		return faded
	
	@staticmethod
	def sunset(text):
		"""Orange to purple gradient."""
		system(""); faded = ""
		red = 255
		blue = 0
		for line in text.splitlines():
			faded += (f"\033[38;2;{red};100;{blue}m{line}\033[0m\n")
			if not red == 128:
				red -= 12
				blue += 12
				if red < 128:
					red = 128
				if blue > 128:
					blue = 128
		return faded
	
	@staticmethod
	def horizontal_rainbow(text, width=80):
		"""Creates a rainbow gradient across a single line of text."""
		system("")
		if not text:
			return ""
		
		result = ""
		text_length = len(text)
		for i, char in enumerate(text):
			# Calculate hue based on position (0-360 degrees in HSV color space)
			hue = int(360 * (i / width) % 360)
			
			# Convert HSV to RGB with full saturation and value
			h = hue / 60
			c = 255  # Full color intensity
			x = int(c * (1 - abs(h % 2 - 1)))
			
			if 0 <= h < 1: r, g, b = c, x, 0
			elif 1 <= h < 2: r, g, b = x, c, 0
			elif 2 <= h < 3: r, g, b = 0, c, x
			elif 3 <= h < 4: r, g, b = 0, x, c
			elif 4 <= h < 5: r, g, b = x, 0, c
			else: r, g, b = c, 0, x
			
			result += f"\033[38;2;{r};{g};{b}m{char}\033[0m"
		
		return result
		
	@staticmethod
	def generate_gradient_colors(start_rgb, end_rgb, steps):
		"""
		Generate a list of RGB color values forming a gradient.
		
		Args:
			start_rgb: Starting color as [r, g, b] with values 0-255
			end_rgb: Ending color as [r, g, b] with values 0-255
			steps: Number of colors to generate
			
		Returns:
			List of [r, g, b] values representing the gradient
		"""
		if steps <= 1:
			return [start_rgb]
			
		result = []
		for i in range(steps):
			ratio = i / (steps - 1)
			r = round(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * ratio)
			g = round(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * ratio)
			b = round(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * ratio)
			result.append([r, g, b])
			
		return result