rule SIGNATURE_BASE_APT_Kaspersky_Duqu2_Procexp : FILE
{
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Malicious MSI"
		author = "Florian Roth (Nextron Systems)"
		id = "d7fd48d5-2416-5eff-a751-ece09ce27767"
		date = "2015-06-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/7yKyOj"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_kaspersky_duqu2.yar#L92-L114"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "dd63f0eebc88fa0737905f20dc30dc968df81b7976a86ed8ed5646f7708c4b4a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2422835716066b6bcecb045ddd4f1fbc9486667a"
		hash2 = "b120620b5d82b05fee2c2153ceaf305807fa9f79"
		hash3 = "288ebfe21a71f83b5575dfcc92242579fb13910d"

	strings:
		$x1 = "svcmsi_32.dll" fullword wide
		$x2 = "msi3_32.dll" fullword wide
		$x3 = "msi4_32.dll" fullword wide
		$x4 = "MSI.dll" fullword ascii
		$s1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
		$s2 = "Sysinternals installer" fullword wide
		$s3 = "Process Explorer" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*)) and ( all of ($s*))
}
