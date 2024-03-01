rule SIGNATURE_BASE_CN_Honker_Getsyskey : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetSyskey.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "08f5b5b1-3085-5bf1-9789-023be5a039f8"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L28-L43"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "17cec5e75cda434d0a1bc8cdd5aa268b42633fe9"
		logic_hash = "1f12ea9d62d4aaf695328fb335445f3dae3996595402586d2ee52098e6727d10"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "GetSyskey <SYSTEM registry file> [Output system key file]" fullword ascii
		$s4 = "The system key file \"%s\" is created." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and all of them
}
