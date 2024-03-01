rule SIGNATURE_BASE_Waterbug_Turla_Dropper
{
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla Dropper"
		author = "Symantec Security Response"
		id = "f9683ac7-36f3-5a2a-8b76-e8e2527f4e0d"
		date = "2015-01-22"
		modified = "2023-12-05"
		reference = "http://t.co/rF35OaAXrl"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_waterbug.yar#L50-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6836b8d28fb41d9459f24d22e3c428b022b26885b7dce1caa5b0d5a7a1b7f82b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
		$b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}

	condition:
		all of them
}
