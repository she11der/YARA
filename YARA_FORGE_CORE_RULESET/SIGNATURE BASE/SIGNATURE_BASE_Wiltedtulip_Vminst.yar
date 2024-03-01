import "pe"

rule SIGNATURE_BASE_Wiltedtulip_Vminst : FILE
{
	meta:
		description = "Detects malware used in Operation Wilted Tulip"
		author = "Florian Roth (Nextron Systems)"
		id = "5d21e515-eb7b-56ab-acc2-f09065769b2d"
		date = "2017-07-23"
		modified = "2023-12-05"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_wilted_tulip.yar#L62-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "a4559c2f4de60537827d167453751a92c0030ae6ce095a2d64df777e93d4b87a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "930118fdf1e6fbffff579e65e1810c8d91d4067cbbce798c5401cf05d7b4c911"

	strings:
		$x1 = "\\C++\\Trojan\\Target\\" ascii
		$s1 = "%s\\system32\\rundll32.exe" fullword wide
		$s2 = "$C:\\Windows\\temp\\l.tmp" fullword wide
		$s3 = "%s\\svchost.exe" fullword wide
		$s4 = "args[10] is %S and command is %S" fullword ascii
		$s5 = "LOGON USER FAILD " fullword ascii
		$s6 = "vminst.tmp" fullword wide
		$s7 = "operator co_await" fullword ascii
		$s8 = "?ReflectiveLoader@@YGKPAX@Z" fullword ascii
		$s9 = "%s -k %s" fullword wide
		$s10 = "ERROR in %S/%d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*) or 5 of ($s*))
}
