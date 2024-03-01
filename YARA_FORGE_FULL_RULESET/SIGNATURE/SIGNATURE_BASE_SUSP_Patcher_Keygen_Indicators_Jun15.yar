rule SIGNATURE_BASE_SUSP_Patcher_Keygen_Indicators_Jun15 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset"
		author = "Florian Roth (Nextron Systems)"
		id = "4dd65e4b-8178-5576-9740-b3c80a8127e2"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1825-L1841"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e32f5de730e324fb386f97b6da9ba500cf3a4f8d"
		logic_hash = "07735c380cf34aaabd5cc0e1b38e32b3d4ad86b7bb184188d446df537f66775e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<description>Patch</description>" fullword ascii
		$s2 = "\\dup2patcher.dll" ascii
		$s3 = "load_patcher" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and all of them
}
