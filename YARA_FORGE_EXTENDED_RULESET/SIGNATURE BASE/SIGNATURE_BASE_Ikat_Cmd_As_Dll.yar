import "pe"

rule SIGNATURE_BASE_Ikat_Cmd_As_Dll
{
	meta:
		description = "iKAT toolset file cmd.dll ReactOS file cloaked"
		author = "Florian Roth (Nextron Systems)"
		id = "8d15b4b6-25f3-556c-bfa8-eba503c9c649"
		date = "2014-05-11"
		modified = "2023-12-05"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L866-L884"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b5d0ba941efbc3b5c97fe70f70c14b2050b8336a"
		logic_hash = "3f8390fb6eb16749e63379222a5899b811e7ccd6b3b219b60d7a621fd4595e7b"
		score = 65
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "cmd.exe" fullword wide
		$s2 = "ReactOS Development Team" fullword wide
		$s3 = "ReactOS Command Processor" fullword wide
		$ext = "extension: .dll" nocase

	condition:
		all of ($s*) and $ext
}
