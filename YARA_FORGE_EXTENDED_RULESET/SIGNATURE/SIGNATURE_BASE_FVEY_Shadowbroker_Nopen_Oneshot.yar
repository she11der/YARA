rule SIGNATURE_BASE_FVEY_Shadowbroker_Nopen_Oneshot
{
	meta:
		description = "Auto-generated rule - file oneshot.example"
		author = "Florian Roth (Nextron Systems)"
		id = "6a6b5426-f559-5668-a2ed-982801933302"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L306-L319"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "19aa32aafaaccc6697bbaff642d996554eccf2261d23071cfb8599ea0eea628b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a85b260d6a53ceec63ad5f09e1308b158da31062047dc0e4d562d2683a82bf9a"

	strings:
		$s1 = "/sbin/sh -c (mkdir /tmp/.X11R6; cd /tmp/.X11R6 && telnet" ascii

	condition:
		1 of them
}
