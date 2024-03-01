import "pe"

rule FIREEYE_RT_APT_Backdoor_Win_GORAT_4 : FILE
{
	meta:
		description = "Verifies that the sample is a Windows PE that is less than 10MB in size and exports numerous functions that are known to be exported by the Gorat implant. This is done in an effort to provide detection for packed samples that may not have other strings but will need to replicate exports to maintain functionality."
		author = "FireEye"
		id = "fa3bcaad-c210-5b9c-8567-fe85b8e78055"
		date = "2021-03-03"
		modified = "2021-03-03"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/REDFLARE (Gorat)/production/yara/APT_Backdoor_Win_GORAT_4.yar#L5-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		hash = "f59095f0ab15f26a1ead7eed8cdb4902"
		logic_hash = "ec201614cb91fae9d7c89febfa22dfd6ba7f353e0eeb0b2fec6c8d887992e79e"
		score = 75
		quality = 25
		tags = "FILE"
		rev = 8

	strings:
		$mz = "MZ"

	condition:
		$mz at 0 and uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <10MB and pe.exports("MemoryCallEntryPoint") and pe.exports("MemoryDefaultAlloc") and pe.exports("MemoryDefaultFree") and pe.exports("MemoryDefaultFreeLibrary") and pe.exports("MemoryDefaultGetProcAddress") and pe.exports("MemoryDefaultLoadLibrary") and pe.exports("MemoryFindResource") and pe.exports("MemoryFindResourceEx") and pe.exports("MemoryFreeLibrary") and pe.exports("MemoryGetProcAddress") and pe.exports("MemoryLoadLibrary") and pe.exports("MemoryLoadLibraryEx") and pe.exports("MemoryLoadResource") and pe.exports("MemoryLoadString") and pe.exports("MemoryLoadStringEx") and pe.exports("MemorySizeofResource") and pe.exports("callback") and pe.exports("crosscall2") and pe.exports("crosscall_386")
}
