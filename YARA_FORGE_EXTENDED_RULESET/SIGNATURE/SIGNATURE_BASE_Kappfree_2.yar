rule SIGNATURE_BASE_Kappfree_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "6c7b4a99-b5ab-5fd6-b130-7c30b84b7171"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2278-L2294"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		logic_hash = "1862f1283e8a268f523b3922b3630ebbca9a81cc5aed19e5068315e6346d25c2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "kappfree.dll" fullword ascii
		$s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
		$s3 = "' introuvable !" fullword wide
		$s4 = "kiwi\\mimikatz" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 2 of them
}
