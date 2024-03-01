rule SIGNATURE_BASE_APT30_Sample_34 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "a4802e13-4151-5f17-ba91-dcf9ef6b52bb"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L941-L960"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "216868edbcdd067bd2a9cce4f132d33ba9c0d818"
		logic_hash = "2406f9613585669f88c389ea9729a089f6aef13fba46d60b713f51cd3a946b5d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "dizhi.gif" ascii
		$s1 = "eagles.vip.nse" ascii
		$s4 = "o%S:S0" ascii
		$s5 = "la/4.0" ascii
		$s6 = "s#!<4!2>s02==<'s1" ascii
		$s7 = "HlobalAl" ascii
		$s9 = "vcMicrosoftHaveAck7" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
