rule SIGNATURE_BASE_Apt_RU_Moonlightmaze_Encrypted_Keylog : FILE
{
	meta:
		description = "Rule to detect Moonlight Maze encrypted keylogger logs"
		author = "Kaspersky Lab"
		id = "f0d464f0-3955-5f41-a57f-8aa225e1171d"
		date = "2017-03-27"
		modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_moonlightmaze.yar#L204-L222"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "593f6f2148ddb52e2beee72a48135cd83f126edfdb263b471432d17273e536db"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$a1 = {47 01 22 2A 6D 3E 39 2C}

	condition:
		uint32(0)==0x2a220147 and ($a1 at 0)
}
