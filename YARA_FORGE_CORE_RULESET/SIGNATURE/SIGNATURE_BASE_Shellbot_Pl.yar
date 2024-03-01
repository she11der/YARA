rule SIGNATURE_BASE_Shellbot_Pl
{
	meta:
		description = "Semi-Auto-generated  - file shellbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "07c145b1-c9f7-564a-b354-a6d2072f380c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3708-L3722"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b2a883bc3c03a35cfd020dd2ace4bab8"
		logic_hash = "5db224e4fe8608bb53f044ca6c0361dc66cadd58c6d4ea5ab4f8ae14ebde0e6e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "ShellBOT"
		$s1 = "PacktsGr0up"
		$s2 = "CoRpOrAtIoN"
		$s3 = "# Servidor de irc que vai ser usado "
		$s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"

	condition:
		2 of them
}
