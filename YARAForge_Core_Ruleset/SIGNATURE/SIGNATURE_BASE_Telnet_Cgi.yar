rule SIGNATURE_BASE_Telnet_Cgi
{
	meta:
		description = "Semi-Auto-generated  - file telnet.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "4ca3dace-cd80-58e4-a4de-47dcc64dac0e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4821-L4833"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "dee697481383052980c20c48de1598d1"
		logic_hash = "689c1d43c64aa7469989686c60fc9ab46acde42fdf3c1157bae1e2b8373c845f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "W A R N I N G: Private Server"
		$s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
		$s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"

	condition:
		1 of them
}