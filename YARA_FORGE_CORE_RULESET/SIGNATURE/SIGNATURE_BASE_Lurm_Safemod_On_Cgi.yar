rule SIGNATURE_BASE_Lurm_Safemod_On_Cgi
{
	meta:
		description = "Semi-Auto-generated  - file lurm_safemod_on.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "74e77260-a547-5553-8430-2620f8549f50"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3886-L3898"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "5ea4f901ce1abdf20870c214b3231db3"
		logic_hash = "d308ad6cda92fa437b9a4c46cd1b97fb0138aa8d0010256bda56a64ced1c7875"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Network security team :: CGI Shell" fullword
		$s1 = "#########################<<KONEC>>#####################################" fullword
		$s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword

	condition:
		1 of them
}
