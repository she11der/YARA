rule SIGNATURE_BASE_Brc4_Shellcode
{
	meta:
		description = "Hunts for shellcode opcode used in Badger x86/x64 till release v1.2.9"
		author = "@ninjaparanoid"
		id = "7e899d2f-332b-53f7-b9e6-cfde2bce6223"
		date = "2022-11-19"
		modified = "2023-12-05"
		reference = "https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/brc4.yara"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/hktl_bruteratel_c4.yar#L263-L290"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "a2816eb0316cebc96569847c17eae3bc50b988b07aa471176a09695fcefc21ec"
		score = 75
		quality = 83
		tags = ""
		version = "last version"
		arch_context = "x64"

	strings:
		$shellcode_x64_Start = { 55 50 53 51 52 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 }
		$shellcode_x64_End = { 5B 5E 5F 41 5C 41 5D 41 5E 41 5F 5D C3 }
		$shellcode_x64_StageEnd = { 5C 41 5F 41 5E 41 5D 41 5C 41 5B 41 5A 41 59 41 58 5F 5E 5A 59 5B 58 5D C3 }
		$funcHash1 = { 5B BC 4A 6A }
		$funcHash2 = { 5D 68 FA 3C }
		$funcHash3 = { AA FC 0D 7C }
		$funcHash4 = { 8E 4E 0E EC }
		$funcHash5 = { B8 12 DA 00 }
		$funcHash6 = { 07 C4 4C E5 }
		$funcHash7 = { BD CA 3B D3 }
		$funcHash8 = { 89 4D 39 8C }
		$hashFuncx64 = { EB 20 0F 1F 44 00 00 44 0F B6 C8 4C 89 DA 41 83 E9 20 4D 63 C1 4B 8D 04 10 49 39 CB 74 21 49 83 C3 01 41 89 C2 }
		$hashFuncx86 = { EB 07 8D 74 26 00 83 C2 01 0F B6 31 C1 C8 0D 89 F1 8D 5C 30 E0 01 F0 80 F9 61 89 D1 0F 43 C3 39 D7 75 E3 }

	condition:
		(pe.machine==pe.MACHINE_AMD64 and (2 of ($shellcode*) or all of ($funcHash*) and $hashFuncx64)) or (pe.machine==pe.MACHINE_I386 and ( all of ($funcHash*) and $hashFuncx86))
}