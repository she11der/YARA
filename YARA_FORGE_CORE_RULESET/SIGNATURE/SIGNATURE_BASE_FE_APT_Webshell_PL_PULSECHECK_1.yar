rule SIGNATURE_BASE_FE_APT_Webshell_PL_PULSECHECK_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "f375fdd8-567b-569b-85f4-af54a35d2a93"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_pulsesecure.yar#L116-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "a1dcdf62aafc36dd8cf64774dea80d79fb4e24ba2a82adf4d944d9186acd1cc1"
		logic_hash = "aba457dd33232ef37ca145c5b7cd9c5fe809730339a55c5e90ac46b4a136f6cb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$r1 = /while[\x09\x20]{0,32}\(<\w{1,64}>\)[\x09\x20]{0,32}\{\s{1,256}\$\w{1,64}[\x09\x20]{0,32}\.=[\x09\x20]{0,32}\$_;\s{0,256}\}/
		$s1 = "use Crypt::RC4;"
		$s2 = "use MIME::Base64"
		$s3 = "MIME::Base64::decode("
		$s4 = "popen("
		$s5 = " .= $_;"
		$s6 = "print MIME::Base64::encode(RC4("
		$s7 = "HTTP_X_"

	condition:
		$s1 and $s2 and (@s3[1]<@s4[1]) and (@s4[1]<@s5[1]) and (@s5[1]<@s6[1]) and (#s7>2) and $r1
}
