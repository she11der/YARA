rule SIGNATURE_BASE_Kappfree : FILE
{
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "eb9c1324-5d82-57ab-bd48-98c984b45b32"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2207-L2222"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e57e79f190f8a24ca911e6c7e008743480c08553"
		logic_hash = "b1b644f9b033ac8372369e81628ee3f6fe094f80d11b8f4f6c192a5e81d2e543"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "kappfree.dll" fullword ascii
		$s3 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
