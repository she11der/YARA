rule SIGNATURE_BASE_Rombertik_Carbongrabber_Builder_Server : FILE
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik Builder Server - file Server.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "742003a2-3716-5ad9-a720-b9e2be71554a"
		date = "2015-05-05"
		modified = "2023-12-05"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_rombertik_carbongrabber.yar#L94-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "895fab8d55882eac51d4b27a188aa67205ff0ae5"
		logic_hash = "693c92128166c72aded066fa66eef906a9f6027c65b889f3a487a38382f29982"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "C:\\WINDOWS\\system32\\svchost.exe" fullword ascii
		$s3 = "Software\\Microsoft\\Windows\\Currentversion\\RunOnce" fullword ascii
		$s4 = "chrome.exe" fullword ascii
		$s5 = "firefox.exe" fullword ascii
		$s6 = "chrome.dll" fullword ascii
		$s7 = "@KERNEL32.DLL" fullword wide
		$s8 = "Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome" ascii
		$s10 = "&post=" fullword ascii
		$s11 = "&host=" fullword ascii
		$s12 = "Ws2_32.dll" fullword ascii
		$s16 = "&browser=" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and 8 of them
}
