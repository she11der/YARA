rule GCTI_Cobaltstrike_Resources_Template_X86_Vba_V3_8_To_V4_X
{
	meta:
		description = "Cobalt Strike's resources/template.x86.vba signature for versions v3.8 to v4.x"
		author = "gssincla@google.com"
		id = "11c7758e-93b2-5fe3-873d-b98de579d2b4"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/CobaltStrike/CobaltStrike__Resources_Template_x86_Vba_v3_8_to_v4_x.yara#L17-L37"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		logic_hash = "7114515477d82651806eccef34f599f6ffd4614f987dee29417ac6ef7a1a1c38"
		score = 75
		quality = 85
		tags = ""

	strings:
		$createstuff = "Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"" nocase
		$allocstuff = "Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"" nocase
		$writestuff = "Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"" nocase
		$runstuff = "Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"" nocase
		$vars = "Dim rwxpage As Long" nocase
		$res = "RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)"
		$rwxpage = "AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)"

	condition:
		all of them and @vars[1]<@res[1] and @allocstuff[1]<@rwxpage[1]
}
