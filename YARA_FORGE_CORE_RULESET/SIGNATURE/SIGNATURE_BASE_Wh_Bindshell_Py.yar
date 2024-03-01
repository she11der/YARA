rule SIGNATURE_BASE_Wh_Bindshell_Py
{
	meta:
		description = "Semi-Auto-generated  - file wh_bindshell.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "b7acbfe7-fd28-5832-9af2-1c5befe4bbab"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3873-L3885"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "fab20902862736e24aaae275af5e049c"
		logic_hash = "e38a4f5c23371705f9bbf2db8e65d68074554edc1022576166e76d40e06bc039"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "#Use: python wh_bindshell.py [port] [password]"
		$s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
		$s3 = "#bugz: ctrl+c etc =script stoped=" fullword

	condition:
		1 of them
}
