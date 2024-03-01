rule SIGNATURE_BASE_CN_Honker_HASH_32 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 32.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a9b5b753-2028-53be-9ac8-50ec910860c3"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1210-L1226"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "bf4a8b4b3e906e385feab5ea768f604f64ba84ea"
		logic_hash = "819e70979ae1d5e237bbadaa52b504c566b4b7436747ceb0d72e206e4fc45708"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "[Undefined OS version]  Major: %d Minor: %d" fullword ascii
		$s8 = "Try To Run As Administrator ..." fullword ascii
		$s9 = "Specific LUID NOT found" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and all of them
}
