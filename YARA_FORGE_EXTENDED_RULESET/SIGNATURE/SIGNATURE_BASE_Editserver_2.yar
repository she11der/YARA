rule SIGNATURE_BASE_Editserver_2
{
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bd254bd9-fd23-5807-9347-2a559089b7c5"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8503-L8516"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"
		logic_hash = "c581936928ce0f1061feb5665c743f14f12a9f875e360f40cc064f3047b23adf"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "@HOTMAIL.COM"
		$s1 = "Press Any Ke"
		$s3 = "glish MenuZ"

	condition:
		all of them
}
