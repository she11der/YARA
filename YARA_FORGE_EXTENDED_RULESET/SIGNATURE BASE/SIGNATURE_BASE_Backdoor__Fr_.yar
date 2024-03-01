rule SIGNATURE_BASE_Backdoor__Fr_
{
	meta:
		description = "Webshells Auto-generated - file BackDooR (fr).php"
		author = "Florian Roth (Nextron Systems)"
		id = "fd0c77e8-18b7-5eb4-8ed4-87ee4c864683"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8011-L8022"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a79cac2cf86e073a832aaf29a664f4be"
		logic_hash = "6c16c200712015eed71aeb119e46bad5f93445a8f719d98ef31f9012cb3551ae"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "

	condition:
		all of them
}
