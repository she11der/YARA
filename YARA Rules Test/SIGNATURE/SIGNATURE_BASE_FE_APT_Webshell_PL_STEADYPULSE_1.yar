rule SIGNATURE_BASE_FE_APT_Webshell_PL_STEADYPULSE_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "49457fbb-9288-565f-909d-e8228c21c1e4"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_pulsesecure.yar#L265-L284"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "168976797d5af7071df257e91fcc31ce1d6e59c72ca9e2f50c8b5b3177ad83cc"
		logic_hash = "a0e3ebdd02ccf5cc8fc0a83c1d0224aed45dc5094eb85bd855e5b74b34e3aaaf"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "parse_parameters"
		$s2 = "s/\\+/ /g"
		$s3 = "s/%(..)/pack("
		$s4 = "MIME::Base64::encode($"
		$s5 = "$|=1;"
		$s6 = "RC4("
		$s7 = "$FORM{'cmd'}"

	condition:
		all of them
}