rule SIGNATURE_BASE_Empire_Skeleton_Key : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file skeleton_key.py"
		author = "Florian Roth (Nextron Systems)"
		id = "d508e09e-13e8-5866-bb5b-0d886f960bb5"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_empire.yar#L153-L170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3d02f16dcc38faaf5e97e4c5dbddf761f2816004775e6af8826cde9e29bb750f"
		logic_hash = "910451b2b2ed7cb5f7891d97d15e49da24b182adc903926f539fc4bfe589f2d5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "script += \"Invoke-Mimikatz -Command '\\\"\" + command + \"\\\"';\"" fullword ascii
		$s2 = "script += '\"Skeleton key implanted. Use password \\'mimikatz\\' for access.\"'" fullword ascii
		$s3 = "command = \"misc::skeleton\"" fullword ascii
		$s4 = "\"ONLY APPLICABLE ON DOMAIN CONTROLLERS!\")," fullword ascii

	condition:
		filesize <6KB and 2 of them
}
