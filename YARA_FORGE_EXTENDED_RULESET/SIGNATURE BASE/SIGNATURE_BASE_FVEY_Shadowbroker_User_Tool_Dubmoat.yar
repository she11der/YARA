rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Dubmoat
{
	meta:
		description = "Auto-generated rule - file user.tool.dubmoat.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "d6c0a00b-dda9-587f-a867-f3b632edd494"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L195-L209"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "368c0a6a1db0003e3a2e4ec5e42a5b5563ea1c2cb89db1751226891e1f7181d8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "bcd4ee336050488f5ffeb850d8eaa11eec34d8ba099b370d94d2c83f08a4d881"

	strings:
		$s1 = "### Verify version on target:" fullword ascii
		$s2 = "/current/bin/ExtractData ./utmp > dub.TARGETNAME" fullword ascii

	condition:
		1 of them
}
