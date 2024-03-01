rule SIGNATURE_BASE_CN_Honker_Exp_Iis7 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iis7.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "edfafc9a-032a-5ccb-9a1f-faeab0dfa31d"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L102-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
		logic_hash = "91ceec96297e5cc027e261fd708899787b9be4ac15e209e0734a3b8563ae31b5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s4 = "WinSta0\\Default" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
