rule SIGNATURE_BASE_FVEY_Shadowbroker_Gen_Readme2
{
	meta:
		description = "Auto-generated rule - from files user.tool.orleansstride.COMMON, user.tool.curserazor.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "5959d881-2989-582c-abe2-48c76ce0e995"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L374-L389"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "eb68c415d64d1db3d4bb0f4ad994bd050cb2287e4dc7b3ac57549f818a7914d8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "18dfd74c3e0bfb1c21127cf3382ba1d9812efdf3e992bd666d513aaf3519f728"
		hash2 = "f4b728c93dba20a163b59b4790f29aed1078706d2c8b07dc7f4e07a6f3ecbe93"

	strings:
		$x1 = "#####  Upload the encrypted phone list as awk, modify each parser command to have the" fullword ascii

	condition:
		1 of them
}
