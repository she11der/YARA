import "pe"

rule SIGNATURE_BASE_Wiltedtulip_Windows_UM_Task
{
	meta:
		description = "Detects a Windows scheduled task as used in Operation Wilted Tulip"
		author = "Florian Roth (Nextron Systems)"
		id = "d827584e-8298-56e4-8466-90950d1f286e"
		date = "2017-07-23"
		modified = "2023-12-05"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_wilted_tulip.yar#L90-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cfc2d231b6be798172e5d7ffc525842c7eed6d78a145c401136452c46f21e3b2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4c2fc21a4aab7686877ddd35d74a917f6156e48117920d45a3d2f21fb74fedd3"

	strings:
		$r1 = "<Command>C:\\Windows\\syswow64\\rundll32.exe</Command>" fullword wide
		$p1 = "<Arguments>\"C:\\Users\\public\\" wide
		$c1 = "svchost64.swp\",checkUpdate" wide ascii
		$c2 = "svchost64.swp,checkUpdate" wide ascii

	condition:
		($r1 and $p1) or 1 of ($c*)
}
