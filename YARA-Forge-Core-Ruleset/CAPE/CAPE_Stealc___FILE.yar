rule CAPE_Stealc___FILE
{
	meta:
		description = "Stealc Payload"
		author = "kevoreilly"
		id = "edfc9a9e-1ac8-53e1-a27c-cc8a095315c6"
		date = "2024-01-19"
		modified = "2024-01-19"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/data/yara/CAPE/Stealc.yar#L1-L15"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/LICENSE"
		hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
		logic_hash = "f63952cabf40b1444d88182ae3b257406b8fa2388f5b0a5f7bd3cd1cf96e0f6f"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Stealc Payload"

	strings:
		$nugget1 = {68 04 01 00 00 6A 00 FF 15 [4] 50 FF 15}
		$nugget2 = {25 FF 00 00 80 79 07 48 0D 00 FF FF FF 40}
		$nugget3 = {68 80 00 00 00 6A 02 (56|6A 00) 6A 03 68 00 00 00 40}
		$nugget4 = {64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC}

	condition:
		uint16(0)==0x5A4D and 2 of them
}