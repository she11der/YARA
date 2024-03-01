rule SIGNATURE_BASE_FVEY_Shadowbroker_Strifeworld
{
	meta:
		description = "Auto-generated rule - file strifeworld.1"
		author = "Florian Roth (Nextron Systems)"
		id = "a15c2034-8394-5e62-a5f0-d1506c19e585"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L211-L225"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2b113b042fd62109ee3ee39515fbd22f3898abf320d75f1288ea88e40b3444c0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "222b00235bf143645ad0d55b2b6839febc5b570e3def00b77699915a7c9cb670"

	strings:
		$s4 = "-p -n.\" strifeworld" fullword ascii
		$s5 = "Running STRIFEWORLD not protected" ascii

	condition:
		1 of them
}
