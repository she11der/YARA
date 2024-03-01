rule SIGNATURE_BASE_Smartniff : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Smartniff.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3d169126-1b43-5545-a106-7c38a6a49499"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2224-L2239"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "67609f21d54a57955d8fe6d48bc471f328748d0a"
		logic_hash = "bac770ae3c8e7f619da0b0ff4243716ff8212dce0f36c08c127af892548fe0b6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "smsniff.exe" fullword wide
		$s2 = "support@nirsoft.net0" fullword ascii
		$s3 = "</requestedPrivileges></security></trustInfo></assembly>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
