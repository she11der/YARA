rule SIGNATURE_BASE_Win32_Klock : FILE
{
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "dd17a8e2-54af-5967-937a-d83feceab891"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2326-L2341"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7addce4434670927c4efaa560524680ba2871d17"
		logic_hash = "e9f1d38de15ce06d55cf276e0f2becd9f9dbf5bd22f9061de03761d7ccdd3e60"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "klock.dll" fullword ascii
		$s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
		$s3 = "klock de mimikatz pour Windows" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <250KB and all of them
}
