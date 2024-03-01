rule SECUINFRA_RANSOM_Magniber_ISO_Jan23 : FILE
{
	meta:
		description = "Detects Magniber Ransomware ISO files from fake Windows Update delivery method"
		author = "SECUINFRA Falcon Team"
		id = "6d5a937d-ac31-5c59-8e93-3fadc772d132"
		date = "2023-01-13"
		modified = "2023-01-13"
		reference = "https://twitter.com/SI_FalconTeam/status/1613540054382559234"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Malware/RANSOM_Magniber_ISO_Jan23.yar#L1-L24"
		license_url = "N/A"
		hash = "4dcbcc070e7e3d0696c777b63e185406e3042de835b734fe7bb33cc12e539bf6"
		logic_hash = "238baa794f4a87102534f7d6901819aa1b5dbb8156d56fb311e9fb1a6bc77f30"
		score = 75
		quality = 68
		tags = "FILE"
		tlp = "CLEAR"

	strings:
		$magic = {43 44 30 30 31}
		$tool = {55 4C 54 52 41 49 53 4F 00 39 2E 37 2E 36 2E 33 38 32 39}
		$msiMagic = {D0 CF 11 E0 A1 B1 1A E1}
		$dosString = "!This program cannot be run in DOS mode" ascii
		$lnkMagic = {4C 00 00 00}

	condition:
		filesize >200KB and filesize <800KB and all of them
}
