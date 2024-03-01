rule SIGNATURE_BASE_Hkdoordll
{
	meta:
		description = "Webshells Auto-generated - file hkdoordll.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "c4cfb575-89c3-5a72-8bf5-234d4284fe9d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8262-L8273"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b715c009d47686c0e62d0981efce2552"
		logic_hash = "a3c4d262b59cdf82390c0457810505e9e7a18c9b26ba4524bc368fd2141ec306"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"

	condition:
		all of them
}
