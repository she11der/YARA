import "pe"

rule DITEKSHEN_INDICATOR_TOOL_ENC_Bestcrypt : FILE
{
	meta:
		description = "Detects BestEncrypt commercial disk encryption and wiping software"
		author = "ditekSHen"
		id = "30c3c17c-c951-5b14-80ba-eec7b2195985"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_tools.yar#L442-L453"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "77d338c6f3e4b733cb31eb1ae05e4ce8631812f7161bc70074a3fe1dee9df770"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$s1 = "BestCrypt Volume Encryption" wide
		$s2 = "BCWipe for " wide
		$s3 = "Software\\Jetico\\BestCrypt" wide
		$s4 = "%c:\\EFI\\Jetico\\" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}
