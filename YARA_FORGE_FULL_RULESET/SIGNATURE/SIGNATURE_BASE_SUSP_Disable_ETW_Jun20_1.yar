rule SIGNATURE_BASE_SUSP_Disable_ETW_Jun20_1
{
	meta:
		description = "Detects method to disable ETW in ENV vars before executing a program"
		author = "Florian Roth (Nextron Systems)"
		id = "ea5dee09-959e-5ef2-8f84-5497bdef0a05"
		date = "2020-06-06"
		modified = "2023-12-05"
		reference = "https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_suspicious_strings.yar#L387-L405"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "182ad2512bcfbcd92d13380113b32982eb367e458019f07038a12f494dfbebb6"
		score = 65
		quality = 85
		tags = ""

	strings:
		$x1 = "set COMPlus_ETWEnabled=0" ascii wide fullword
		$x2 = "$env:COMPlus_ETWEnabled=0" ascii wide fullword
		$s1 = "Software\\Microsoft.NETFramework" ascii wide
		$sa1 = "/v ETWEnabled" ascii wide fullword
		$sa2 = " /d 0" ascii wide
		$sb4 = "-Name ETWEnabled"
		$sb5 = " -Value 0 "

	condition:
		1 of ($x*) or 3 of them
}
