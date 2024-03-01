rule SIGNATURE_BASE_Win32_Buzus_Softpulse : FILE
{
	meta:
		description = "Trojan Buzus / Softpulse"
		author = "Florian Roth (Nextron Systems)"
		id = "3b555916-030a-5773-b2f1-e995fc81b697"
		date = "2015-05-13"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_buzus_softpulse.yar#L2-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2f6df200e63a86768471399a74180466d2e99ea9"
		logic_hash = "49625594db57e9d629860970c20493b76e554addc2edb41adba64673a820a94b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "pi4izd6vp0.com" fullword ascii
		$s1 = "SELECT * FROM Win32_Process" fullword wide
		$s4 = "CurrentVersion\\Uninstall\\avast" fullword wide
		$s5 = "Find_RepeatProcess" fullword ascii
		$s6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\" wide
		$s7 = "myapp.exe" fullword ascii
		$s14 = "/c ping -n 1 www.google" wide

	condition:
		uint16(0)==0x5a4d and (($x1 and 2 of ($s*)) or all of ($s*))
}
