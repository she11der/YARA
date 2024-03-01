import "pe"

rule SIGNATURE_BASE_WMI_Vbs : APT
{
	meta:
		description = "WMI Tool - APT"
		author = "Florian Roth (Nextron Systems)"
		id = "b367306a-38d8-5f4d-8f09-2bf025831f0a"
		date = "2013-11-29"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2943-L2957"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "94163981c1a80838d1bea1b21f713f1d8fbdac8704319d1a145f0b4f6d8ff3f6"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		confidential = false

	strings:
		$s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"

	condition:
		all of them
}
