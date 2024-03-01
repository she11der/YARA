rule SIGNATURE_BASE_Hacktool_This_Cruft : FILE
{
	meta:
		description = "Detects string 'This cruft' often used in hack tools like netcat or cryptcat and also mentioned in Project Sauron report"
		author = "Florian Roth (Nextron Systems)"
		id = "a39de541-19b5-5b7e-a3dc-51a5309181e5"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_project_sauron_extras.yar#L106-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "875c34e8048c3f98afc97683d0b3086c3396753cd9fb14bc68681c63ed77fd51"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "This cruft" fullword

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and $x1)
}
