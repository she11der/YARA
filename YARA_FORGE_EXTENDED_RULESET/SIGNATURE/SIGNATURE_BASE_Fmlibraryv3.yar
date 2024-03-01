rule SIGNATURE_BASE_Fmlibraryv3
{
	meta:
		description = "Webshells Auto-generated - file fmlibraryv3.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "9b8ef79d-80bb-5a05-91e6-0f2bc3fd3068"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8560-L8571"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c34c248fed6d5a20d8203924a2088acc"
		logic_hash = "a7dc83db26cdda757f626c42022c17bb2764074a3cc5f87b4a3aaa991fac5dc2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"

	condition:
		all of them
}
