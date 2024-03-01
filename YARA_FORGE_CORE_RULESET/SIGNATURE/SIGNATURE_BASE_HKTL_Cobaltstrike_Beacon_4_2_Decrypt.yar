rule SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_4_2_Decrypt
{
	meta:
		description = "Identifies deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2"
		author = "Elastic"
		id = "63b71eef-0af5-5765-b957-ccdc9dde053b"
		date = "2021-03-16"
		modified = "2023-12-05"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_cobaltstrike.yar#L90-L102"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8685b1626c8d263f49ccf129dcd4fe1b42482fcdb37c2e109cedcecaed8c2407"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
		$a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}

	condition:
		any of them
}
