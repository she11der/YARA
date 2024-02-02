rule SIGNATURE_BASE_FE_Webshell_PL_ATRIUM_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "b2663343-0bae-5215-a443-866ab8626bff"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_pulsesecure.yar#L12-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "ca0175d86049fa7c796ea06b413857a3"
		logic_hash = "869b397616495c644beb997602eac84ddcdbacce4c14755c555f5bda36663ca2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "CGI::param("
		$s2 = "system("
		$s3 = /if[\x09\x20]{0,32}\(CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)\)\s{0,128}\{[\x09\x20]{0,32}print [\x22\x27]Cache-Control: no-cache\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}print [\x22\x27]Content-type: text\/html\\n\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}my \$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)[\x09\x20]{0,32};\s{0,128}system\([\x22\x27]\$/

	condition:
		all of them
}