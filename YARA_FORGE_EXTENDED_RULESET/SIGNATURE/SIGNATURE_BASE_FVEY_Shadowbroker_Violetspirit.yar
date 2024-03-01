rule SIGNATURE_BASE_FVEY_Shadowbroker_Violetspirit
{
	meta:
		description = "Auto-generated rule - file violetspirit.README"
		author = "Florian Roth (Nextron Systems)"
		id = "4efea734-8cbc-53f7-bf92-5b3253721a81"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L73-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "01a45feb5c9f9cfe8834306993c53b1e53d79b89b07106ffec0c81cdebb8b71c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"

	strings:
		$x1 = "-i tgt_ipaddr -h tgt_hostname" fullword ascii

	condition:
		1 of them
}
