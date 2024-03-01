rule SIGNATURE_BASE_Sharpcat : FILE
{
	meta:
		description = "Detects command shell SharpCat - file SharpCat.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "94a7ce40-ac2f-598e-86c5-ee9fde1eeef0"
		date = "2016-06-10"
		modified = "2023-12-05"
		reference = "https://github.com/Cn33liz/SharpCat"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_sharpcat.yar#L8-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4a38812b07b40bdde03049dbff1f9de38cadaf9941ab8b40b84016b1d5cbfd51"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "96dcdf68b06c3609f486f9d560661f4fec9fe329e78bd300ad3e2a9f07e332e9"

	strings:
		$x1 = "ShellZz" fullword ascii
		$s2 = "C:\\Windows\\System32\\cmd.exe" fullword wide
		$s3 = "currentDirectory" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
