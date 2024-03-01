rule SIGNATURE_BASE_Cmdshell
{
	meta:
		description = "Webshells Auto-generated - file cmdShell.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "be256fc4-8dc5-58e4-9ca2-5a1df936b8dd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8890-L8901"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8a9fef43209b5d2d4b81dfbb45182036"
		logic_hash = "5e7c7537b355b162d58b8bce570b1f94a8e6b479856685a245ffaed8f9482680"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if cmdPath=\"wscriptShell\" then"

	condition:
		all of them
}
