rule SIGNATURE_BASE_Windosshell_S1 : FILE
{
	meta:
		description = "Detects simple Windows shell - file s1.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b4e783a2-4a93-5c72-9b09-4692b383ac00"
		date = "2016-03-26"
		modified = "2023-12-05"
		reference = "https://github.com/odzhan/shells/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_winshells.yar#L33-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		logic_hash = "29fcddc549c615ca5cdda60272926671bc1446c3c7b51c9a2fd867b6b68858b2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[ executing cmd.exe" fullword ascii
		$s2 = "[ simple remote shell for windows v1" fullword ascii
		$s3 = "-p <number>  Port number to use (default is 443)" fullword ascii
		$s4 = "usage: s1 <address> [options]" fullword ascii
		$s5 = "[ waiting for connections on %s" fullword ascii
		$s6 = "-l           Listen for incoming connections" fullword ascii
		$s7 = "[ connection from %s" fullword ascii
		$s8 = "[ %c%c requires parameter" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <150KB and 2 of them ) or (5 of them )
}
