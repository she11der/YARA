rule SIGNATURE_BASE_Suspicious_BAT_Strings : FILE
{
	meta:
		description = "Detects a string also used in Netwire RAT auxilliary"
		author = "Florian Roth (Nextron Systems)"
		id = "5fe28555-96c8-54da-b047-7d0a7532a6d2"
		date = "2018-01-05"
		modified = "2023-12-05"
		reference = "https://pastebin.com/8qaiyPxs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_netwire_rat.yar#L32-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e643a5ef41d084e1b1a20be2c56328b72fedddbbce3c79d1e93cc8cfaa633e12"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "ping 192.0.2.2 -n 1" ascii

	condition:
		filesize <600KB and 1 of them
}
