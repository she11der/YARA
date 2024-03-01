rule SIGNATURE_BASE_Darkspy105
{
	meta:
		description = "Webshells Auto-generated - file DarkSpy105.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9d519ccf-fe52-5b82-a39d-c9f86c1089e1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7352-L7363"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f0b85e7bec90dba829a3ede1ab7d8722"
		logic_hash = "0f1c9dba4525f9c30f309500652ed6af647ddf492f483e101fc23c891e15fc85"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"

	condition:
		all of them
}
