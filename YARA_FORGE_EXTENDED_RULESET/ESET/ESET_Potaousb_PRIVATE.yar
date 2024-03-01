private rule ESET_Potaousb_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "98fd84cb-d8e8-5aed-a1ac-f1099be5a5db"
		date = "2015-07-30"
		modified = "2015-07-30"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/potao/PotaoNew.yara#L71-L80"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "8f72afbf3b123ea3914b3eade267bd21f7435fbf9fbde4049ca2600513bb31d9"
		score = 75
		quality = 28
		tags = ""

	strings:
		$mz = { 4d 5a }
		$binary1 = { 33 C0 8B C8 83 E1 03 BA ?? ?? ?? 00 2B D1 8A 0A 32 88 ?? ?? ?? 00 2A C8 FE C9 88 88 ?? ?? ?? 00 40 3D ?? ?? 00 00 7C DA C3 }
		$binary2 = { 55 8B EC 51 56 C7 45 FC 00 00 00 00 EB 09 8B 45 FC 83 C0 01 89 45 FC 81 7D FC ?? ?? 00 00 7D 3D 8B 4D FC 0F BE 89 ?? ?? ?? 00 8B 45 FC 33 D2 BE 04 00 00 00 F7 F6 B8 03 00 00 00 2B C2 0F BE 90 ?? ?? ?? 00 33 CA 2B 4D FC 83 E9 01 81 E1 FF 00 00 00 8B 45 FC 88 88 ?? ?? ?? 00 EB B1 5E 8B E5 5D C3}

	condition:
		($mz at 0) and any of ($binary*)
}
