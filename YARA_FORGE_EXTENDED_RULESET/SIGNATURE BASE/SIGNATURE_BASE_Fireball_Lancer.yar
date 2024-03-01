rule SIGNATURE_BASE_Fireball_Lancer : FILE
{
	meta:
		description = "Detects Fireball malware - file lancer.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "2209bcb4-74a6-5c39-962c-ccd4ce62619e"
		date = "2017-06-02"
		modified = "2023-12-05"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_fireball.yar#L31-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "74df144556121609da0820c319a86a9de0f49eeb2d4b1ed59c3a4d0c1d7788cb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7d68386554e514f38f98f24e8056c11c0a227602ed179d54ed08f2251dc9ea93"

	strings:
		$x1 = "\\instlsp\\Release\\Lancer.pdb" ascii
		$x2 = "lanceruse.dat" fullword wide
		$s1 = "Lancer.dll" fullword ascii
		$s2 = "RunDll32.exe \"" fullword wide
		$s3 = "Micr.dll" fullword wide
		$s4 = "AG64.dll" fullword wide
		$s5 = "\",Start" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and (1 of ($x*) or 3 of ($s*))) or (6 of them )
}
