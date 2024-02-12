rule RUSSIANPANDA_Solardropper
{
	meta:
		description = "SolarMarker first stage detection"
		author = "RussianPanda"
		id = "8e40b001-ae00-5768-bb91-e45264748087"
		date = "2024-01-03"
		modified = "2024-01-03"
		reference = "https://www.esentire.com/blog/solarmarker-to-jupyter-and-back"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1a5f7fbf0094a17dcddaa74b56fb43a231b550af/SolarMarker/solardropper.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "5dccb7be94e814335c0c867f8b3dd8855043375fe9f1235d5519c690fc7df842"
		score = 75
		quality = 85
		tags = ""

	strings:
		$p1 = {2d 00 71 00 71 00 78 00 74 00 72 00 61 00 63 00 74 00 3a 00 22 00 3c 00 66 00 69 00 6c 00 71 00 71 00 6e 00 61 00 6d 00 71 00 71 00 3e 00 22 00}
		$p2 = "deimos.exe"
		$p3 = {5e 00 2d 00 28 00 5b 00 5e 00 3a 00 20 00 5d 00 2b 00 29 00 5b 00 20 00 3a 00 5d 00 3f 00 28 00 5b 00 5e 00 3a 00 5d 00 2a 00 29 00 24 00}

	condition:
		all of ($p*)
}