rule SIGNATURE_BASE_Fireball_Gubed : FILE
{
	meta:
		description = "Detects Fireball malware - file gubed.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "cba2913f-4d9a-5925-ad9a-f5815a635291"
		date = "2017-06-02"
		modified = "2022-12-21"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_fireball.yar#L173-L191"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e8053d8a95d41d81940bbaf7945323849613dbcfe727559a07bc294bd834b65f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e3f69a1fb6fcaf9fd93386b6ba1d86731cd9e5648f7cff5242763188129cd158"

	strings:
		$x1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MRT.exe" fullword wide
		$x2 = "tIphlpapi.dll" fullword wide
		$x3 = "http://%s/provide?clients=%s&reqs=visit.startload" fullword wide
		$x4 = "\\Gubed\\Release\\Gubed.pdb" ascii
		$x5 = "d2hrpnfyb3wv3k.cloudfront.net" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
