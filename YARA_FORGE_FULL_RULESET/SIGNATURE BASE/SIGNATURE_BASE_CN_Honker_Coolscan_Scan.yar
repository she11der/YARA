rule SIGNATURE_BASE_CN_Honker_Coolscan_Scan : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file scan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "781446d2-3363-56c3-9767-c7ac70047b68"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L172-L187"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e1c5fb6b9f4e92c4264c7bea7f5fba9a5335c328"
		logic_hash = "89c7d24d821e907f79ab5630eed13275c5216cff6bf203b5c8f66bb1a178039b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "User-agent:\\s{0,32}(huasai|huasai/1.0|\\*)" fullword ascii
		$s1 = "scan web.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <3680KB and all of them
}
