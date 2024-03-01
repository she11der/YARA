rule SIGNATURE_BASE_X64_Klock : FILE
{
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "7065a4fb-c867-5a94-b6bb-5b60085bea15"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L475-L491"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		logic_hash = "3fe00c08607d20daa055db2f551009ff1c447f1a651d4a78aba91621d53424f5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "klock.dll" fullword ascii
		$s3 = "Erreur : le bureau courant (" wide
		$s4 = "klock de mimikatz pour Windows" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <907KB and all of them
}
