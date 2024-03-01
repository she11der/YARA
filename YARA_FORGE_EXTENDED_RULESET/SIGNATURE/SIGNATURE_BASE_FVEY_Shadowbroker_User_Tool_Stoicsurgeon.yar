rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Stoicsurgeon
{
	meta:
		description = "Auto-generated rule - file user.tool.stoicsurgeon.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "2ff22b17-4922-54d7-bbd8-a5ff40b6ebe5"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L260-L273"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "322599ba7d5536b7f0856980a6caab86de66c02da75bf55e97bf129d08c43031"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "967facb19c9b563eb90d3df6aa89fd7dcfa889b0ba601d3423d9b71b44191f50"

	strings:
		$x1 = "echo -n TARGET_HOSTNAME  | sed '/\\n/!G;s/\\(.\\)\\(.*\\n\\)/&\\2\\1/;//D;s/.//'" fullword ascii

	condition:
		1 of them
}
