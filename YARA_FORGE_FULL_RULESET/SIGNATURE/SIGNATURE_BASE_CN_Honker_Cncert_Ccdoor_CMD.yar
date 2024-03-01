rule SIGNATURE_BASE_CN_Honker_Cncert_Ccdoor_CMD : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "ddd328a8-7ad8-5b26-9deb-3e5da801cd1b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L737-L754"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1c6ed7d817fa8e6534a5fd36a94f4fc2f066c9cd"
		logic_hash = "3c068c3d21de8c071b3eec354f03423d4902ef0156bb9dcad370cf688bc03426"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "CnCerT.CCdoor.CMD.dll" fullword wide
		$s3 = "cmdpath" fullword ascii
		$s4 = "Get4Bytes" fullword ascii
		$s5 = "ExcuteCmd" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <22KB and all of them
}
