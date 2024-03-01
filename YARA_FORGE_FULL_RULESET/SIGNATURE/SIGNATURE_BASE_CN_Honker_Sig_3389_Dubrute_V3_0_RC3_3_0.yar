rule SIGNATURE_BASE_CN_Honker_Sig_3389_Dubrute_V3_0_RC3_3_0 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 3.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "994ad7e9-2019-54b3-84e6-2762a700c939"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L308-L324"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "49b311add0940cf183e3c7f3a41ea6e516bf8992"
		logic_hash = "6d2f6721c942332af1be0b6537e9b9d0b5b3e91eb3912dcd095aa18bccfc4ad5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "explorer.exe http://bbs.yesmybi.net" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s9 = "CryptGenRandom" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <395KB and all of them
}
