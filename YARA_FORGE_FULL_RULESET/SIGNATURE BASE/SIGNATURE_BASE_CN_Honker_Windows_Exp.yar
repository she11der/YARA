rule SIGNATURE_BASE_CN_Honker_Windows_Exp : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file exp.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "148900d0-cf62-5cb0-adbc-52fa8ce8832e"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L326-L341"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "04334c396b165db6e18e9b76094991d681e6c993"
		logic_hash = "6a146545fd12e7603bf1e2ccb9b2d308b13fe2acdb9248a79c80b6c1de37fd73"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "c:\\windows\\system32\\command.com /c " fullword ascii
		$s8 = "OH,Sry.Too long command." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <220KB and all of them
}
