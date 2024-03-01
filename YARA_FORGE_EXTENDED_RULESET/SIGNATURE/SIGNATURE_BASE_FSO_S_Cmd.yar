rule SIGNATURE_BASE_FSO_S_Cmd
{
	meta:
		description = "Webshells Auto-generated - file cmd.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "f7a74f21-aec9-5ee7-a80e-0fe34b977a71"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7676-L7688"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cbe8e365d41dd3cd8e462ca434cf385f"
		logic_hash = "43f3379a57210f0e3b70575313115a7ba3d71359de7c5ac9a6a178b93af3545e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
		$s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"

	condition:
		all of them
}
