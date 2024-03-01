rule SIGNATURE_BASE_SUSP_BAT2EXE_Bdargo_Converted_BAT : FILE
{
	meta:
		description = "Detects binaries created with BDARGO Advanced BAT to EXE converter"
		author = "Florian Roth (Nextron Systems)"
		id = "c9da4184-1530-5525-bdba-2dcc8a221bb1"
		date = "2018-07-28"
		modified = "2022-06-23"
		reference = "https://www.majorgeeks.com/files/details/advanced_bat_to_exe_converter.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_bat2exe.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "978aa25f1abd0cbd36e55da2b1ed4478a3a5b8b814988669c70e219cc2dd1afd"
		score = 45
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d428d79f58425d831c2ee0a73f04749715e8c4dd30ccd81d92fe17485e6dfcda"
		hash1 = "a547a02eb4fcb8f446da9b50838503de0d46f9bb2fd197c9ff63021243ea6d88"

	strings:
		$s1 = "Error #bdembed1 -- Quiting" fullword ascii
		$s2 = "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
		$s3 = "\\a.txt" ascii
		$s4 = "command.com" fullword ascii
		$s6 = "DFDHERGDCV" fullword ascii
		$s7 = "DFDHERGGZV" fullword ascii
		$s8 = "%s%s%s%s%s%s%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 5 of them
}
