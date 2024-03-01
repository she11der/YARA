rule SBOUSSEADEN_Hunt_Procinj_Instrumentationcallback : FILE
{
	meta:
		description = "hunt for possible injection with Instrumentation Callback PE"
		author = "SBousseaden"
		id = "f450bf71-d848-540e-b700-c046662f1cbc"
		date = "2020-07-25"
		modified = "2020-07-25"
		reference = "https://movaxbx.ru/2020/07/24/weaponizing-mapping-injection-with-instrumentation-callback-for-stealthier-process-injection/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_procinj_instrcallback.yara#L1-L21"
		license_url = "N/A"
		logic_hash = "b33dae550bae9508b9fd5b2d6cabf1d4d928792d3988af23cdba34d9d3d03162"
		score = 50
		quality = 71
		tags = "FILE"

	strings:
		$mv1 = "MapViewOfFile3" xor
		$mv2 = "MapViewOfFile3" wide xor
		$mv3 = "NtMapViewOfSectionEx" xor
		$mv4 = "NtMapViewOfSectionEx" wide xor
		$mv5 = {(49 89 CA|4C 8B D1) B8 0F 01 00 00 0F 05 C3}
		$spi1 = "NtSetInformationProcess" xor
		$spi2 = "NtSetInformationProcess" wide xor
		$spi3 = {(49 89 CA|4C 8B D1) B8 1C 00 00 00 0F 05 C3}
		$picb = {BA 28 00 00 00}
		$ss1 = {41 52 50 53 55 57 56 54 41 54 41 55 41 56 41 57}
		$ss2 = {41 5F 41 5E 41 5D 41 5C 5C 5E 5F 5D 5B 58 41 5A}
		$ss3 = {49 89 CA 0F 05 C3}

	condition:
		uint16(0)==0x5a4d and $picb and 1 of ($mv*) and 1 of ($spi*) and 1 of ($ss*)
}
