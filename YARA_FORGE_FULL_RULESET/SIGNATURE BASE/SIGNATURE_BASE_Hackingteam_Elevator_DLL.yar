rule SIGNATURE_BASE_Hackingteam_Elevator_DLL : FILE
{
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "d479c675-b200-56e3-8976-f70b45ea791e"
		date = "2015-07-07"
		modified = "2023-12-05"
		reference = "http://t.co/EG0qtVcKLh"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hackingteam_rules.yar#L33-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b7ec5d36ca702cc9690ac7279fd4fea28d8bd060"
		logic_hash = "f2860c0bb6176f7cc57cb703e9d4235c4cf0b9cc1c0e7c47fb4c8ba47155a616"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\sysnative\\CI.dll" ascii
		$s2 = "setx TOR_CONTROL_PASSWORD" fullword ascii
		$s3 = "mitmproxy0" fullword ascii
		$s4 = "\\insert_cert.exe" ascii
		$s5 = "elevator.dll" fullword ascii
		$s6 = "CRTDLL.DLL" fullword ascii
		$s7 = "fail adding cert" fullword ascii
		$s8 = "DownloadingFile" fullword ascii
		$s9 = "fail adding cert: %s" fullword ascii
		$s10 = "InternetOpenA fail" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 6 of them
}
