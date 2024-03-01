rule SIGNATURE_BASE_Sendmail
{
	meta:
		description = "Webshells Auto-generated - file sendmail.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dd33c2bb-61bf-57b7-82b9-d864097f7a56"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7289-L7301"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "75b86f4a21d8adefaf34b3a94629bd17"
		logic_hash = "bcca9a9380d2695bc277afc9fa72c24cb26ac44c6fbcc87113b017cfe190bdab"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "_NextPyC808"
		$s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"

	condition:
		all of them
}
