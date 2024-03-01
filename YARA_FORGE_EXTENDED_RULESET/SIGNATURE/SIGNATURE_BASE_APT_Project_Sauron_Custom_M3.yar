rule SIGNATURE_BASE_APT_Project_Sauron_Custom_M3 : FILE
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "Florian Roth (Nextron Systems)"
		id = "555b37a2-6a3c-539f-81dc-24c739795510"
		date = "2016-08-09"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_project_sauron_extras.yar#L169-L186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "739414990d112dd16e01831408ba745b04fae7621eb9074f73babbc40b69e1ad"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a4736de88e9208eb81b52f29bab9e7f328b90a86512bd0baadf4c519e948e5ec"

	strings:
		$s1 = "ExampleProject.dll" fullword ascii
		$op0 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 ba }
		$op1 = { ff 15 34 20 00 10 85 c0 59 a3 60 30 00 10 75 04 }
		$op2 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 00 20 00 }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and ( all of ($s*)) and all of ($op*))
}
