rule CAPE_Remcos : FILE
{
	meta:
		description = "Remcos Payload"
		author = "kevoreilly"
		id = "f77295ca-02d5-5b2c-80b8-b6566610bff8"
		date = "2022-05-10"
		modified = "2022-05-10"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/Remcos.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "38142e784ad437d9592353b924f74777bb62e5ed176c811230a2021a437d4710"
		score = 75
		quality = 68
		tags = "FILE"
		cape_type = "Remcos Payload"

	strings:
		$name = "Remcos" nocase
		$time = "%02i:%02i:%02i:%03i"
		$crypto1 = {81 E1 FF 00 00 80 79 ?? 4? 81 C9 00 FF FF FF 4? 8A ?4 8?}
		$crypto2 = {0F B6 [1-7] 8B 45 08 [0-2] 8D 34 07 8B 01 03 C2 8B CB 99 F7 F9 8A 84 95 ?? ?? FF FF 30 06 47 3B 7D 0C 72}

	condition:
		uint16(0)==0x5A4D and ($name) and ($time) and any of ($crypto*)
}
