rule RUSSIANPANDA_Darkgate_Autoit
{
	meta:
		description = "Detects DarkGate AutoIT script"
		author = "RussianPanda"
		id = "b30544b5-88c9-5a84-8582-f4f72b228f24"
		date = "2024-01-26"
		modified = "2024-01-26"
		reference = "https://yara.readthedocs.io/en/stable/writingrules.html?highlight=xor"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/DarkGate/darkgate_autoit.yar#L1-L19"
		license_url = "N/A"
		hash = "e1803b01e3f187355dbeb87a0c91b76c"
		logic_hash = "dda6726d09035d6f61ca331d18ed37f032c6f6a5ab88e1754a21587f4c79ac87"
		score = 75
		quality = 85
		tags = ""

	strings:
		$h = "AU3!EA06"
		$s1 = "just_test.txt" xor(0x01-0xff)
		$s2 = "c:\\temp\\data.txt" xor(0x01-0xff)
		$s3 = "test.txt" xor(0x01-0xff)
		$s4 = "cc.txt" xor(0x01-0xff)
		$s5 = "c:\\temp\\data.txt" xor(0x01-0xff)
		$s6 = "uu.txt" xor(0x01-0xff)

	condition:
		3 of ($s*) and $h
}
