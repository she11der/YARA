rule SIGNATURE_BASE_CN_Honker_Dirdown_Dirdown : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file dirdown.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "80f98131-79bf-580d-87ad-a54a3f14b301"
		date = "2015-06-23"
		modified = "2022-12-21"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1063-L1080"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7b8d51c72841532dded5fec7e7b0005855b8a051"
		logic_hash = "5e8349096b7d07757c3779e13fba87f770a5ef090bc7efe36fd151c7c180edad"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\Decompress\\obj\\Release\\Decompress.pdb" ascii
		$s1 = "Decompress.exe" fullword wide
		$s5 = "Get8Bytes" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <45KB and all of them
}
