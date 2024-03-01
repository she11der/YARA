import "pe"

rule SIGNATURE_BASE_Wiltedtulip_Tdtess : FILE
{
	meta:
		description = "Detects malicious service used in Operation Wilted Tulip"
		author = "Florian Roth (Nextron Systems)"
		id = "0ecb391b-a4f9-5362-bb65-73801ae497de"
		date = "2017-07-23"
		modified = "2023-12-05"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_wilted_tulip.yar#L130-L147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ffd10e06b3a8f3054747443b863070e8726589fc795f816832dbf73c0c34e080"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3fd28b9d1f26bd0cee16a167184c9f4a22fd829454fd89349f2962548f70dc34"

	strings:
		$x1 = "d2lubG9naW4k" fullword wide
		$x2 = "C:\\Users\\admin\\Documents\\visual studio 2015\\Projects\\Export\\TDTESS_ShortOne\\WinService Template\\" ascii
		$s1 = "\\WinService Template\\obj\\x64\\x64\\winlogin" ascii
		$s2 = "winlogin.exe" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or 2 of them ))
}
