rule SIGNATURE_BASE_Shellcode_Apihashing_FIN8_1
{
	meta:
		description = "Detects FIN8 Shellcode APIHashing"
		author = "Frank Boldewin (@r3c0nst)"
		id = "bca5601c-2998-545b-8dd0-ec3c861e6291"
		date = "2021-03-16"
		modified = "2023-12-05"
		reference = "https://www.bitdefender.com/files/News/CaseStudies/study/394/Bitdefender-PR-Whitepaper-BADHATCH-creat5237-en-EN.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fin8.yar#L1-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5d47119a588aa69b3e241618d6dbb9df6117a6751bbff39a1f95340bc26611a7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$APIHashing32bit1 = {81 F7 99 5D 52 69 81 F3 30 D7 00 AB}
		$APIHashing32bit2 = {68 F2 55 03 88 68 65 19 6D 1E}
		$APIHashing32bit3 = {68 9B 59 27 21 C1 E9 17 33 4C 24 10 68 37 5C 32 F4}
		$APIHashing64bit1 = {49 BF 65 19 6D 1E F2 55 03 88 49 BE 37 5C 32 F4 9B 59 27 21}
		$APIHashing64bit2 = {48 B8 99 5D 52 69 30 D7 00 AB}

	condition:
		all of ($APIHashing32bit*) or all of ($APIHashing64bit*)
}
