rule SIGNATURE_BASE_Susp_Powershell_Sep17_1 : FILE
{
	meta:
		description = "Detects suspicious PowerShell script in combo with VBS or JS "
		author = "Florian Roth (Nextron Systems)"
		id = "6d4b9113-173f-5c12-b440-7f1cef9e6ebb"
		date = "2017-09-30"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_susp.yar#L121-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6c8a1e72b2c4685a5a5749d86901b123976092aee373412bf04c62aa32145be8"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8e28521749165d2d48bfa1eac685c985ac15fc9ca5df177d4efadf9089395c56"

	strings:
		$x1 = "Process.Create(\"powershell.exe -nop -w hidden" fullword ascii nocase
		$x2 = ".Run\"powershell.exe -nop -w hidden -c \"\"IEX " ascii
		$s1 = "window.resizeTo 0,0" fullword ascii

	condition:
		( filesize <2KB and 1 of them )
}
