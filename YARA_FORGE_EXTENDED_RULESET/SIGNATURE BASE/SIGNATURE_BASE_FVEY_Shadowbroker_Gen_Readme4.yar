rule SIGNATURE_BASE_FVEY_Shadowbroker_Gen_Readme4
{
	meta:
		description = "Auto-generated rule - from files violetspirit.README, violetspirit.README"
		author = "Florian Roth (Nextron Systems)"
		id = "9e84e4ab-f74a-59e5-aee2-408a68cd673f"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L413-L429"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c19c77d7e7e26e01a9a50fd67cc0a7fd05069def878bf18726c3e115df307cb2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"
		hash2 = "a55fec73595f885e43b27963afb17aee8f8eefe811ca027ef0d7721d073e67ea"

	strings:
		$s1 = "[-v rpc version] : default 4 : Solaris 8 and other patched versions use version 5" fullword ascii
		$s5 = "[-n tcp_port]    : default use portmapper to determine" fullword ascii

	condition:
		1 of them
}
