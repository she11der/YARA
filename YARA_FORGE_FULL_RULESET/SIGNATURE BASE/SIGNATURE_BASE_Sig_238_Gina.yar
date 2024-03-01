import "pe"

rule SIGNATURE_BASE_Sig_238_Gina
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.reg"
		author = "Florian Roth (Nextron Systems)"
		id = "85c19493-e6d4-55e8-8526-6817243e90cf"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1862-L1877"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "324acc52566baf4afdb0f3e4aaf76e42899e0cf6"
		logic_hash = "f0ece7406a31f5a4212da5c4144233c5c45b8120d09267fdf7e291d6c9827384"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\"gina\"=\"gina.dll\"" fullword ascii
		$s1 = "REGEDIT4" fullword ascii
		$s2 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" fullword ascii

	condition:
		all of them
}
