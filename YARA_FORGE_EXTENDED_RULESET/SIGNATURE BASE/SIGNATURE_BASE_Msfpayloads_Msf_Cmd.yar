rule SIGNATURE_BASE_Msfpayloads_Msf_Cmd
{
	meta:
		description = "Metasploit Payloads - file msf-cmd.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "71d42c34-a0b0-5173-8f2f-f48a7af0e4ff"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_metasploit_payloads.yar#L217-L230"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ea44b3d00733eb7d4f924ccaece5265fcd90a462acb954a134b5355ecb0621e5"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"

	strings:
		$x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii

	condition:
		all of them
}
