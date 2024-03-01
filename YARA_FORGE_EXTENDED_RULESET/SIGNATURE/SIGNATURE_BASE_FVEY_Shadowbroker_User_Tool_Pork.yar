rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Pork
{
	meta:
		description = "Auto-generated rule - file user.tool.pork.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "ee5f88b1-6e58-5288-8b80-0d3d188e1ac6"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L227-L242"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c3f9f90f83f3672b101e52f36012c485c29840cf0b2ced00087fb27725fd1545"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9c400aab74e75be8770387d35ca219285e2cedc0c7895225bbe567ce9c9dc078"

	strings:
		$x2 = "packrat -z RAT_REMOTE_NAME" fullword ascii
		$s3 = "./client -t TIME_ADJ SPECIAL_SOURCE_PORT 127.0.0.1 TARG_PORT" ascii
		$s4 = "mkdir TEMP_DIR; cd TEMP_DIR; cat < /dev/tcp/REDIR_IP/RED" ascii

	condition:
		1 of them
}
