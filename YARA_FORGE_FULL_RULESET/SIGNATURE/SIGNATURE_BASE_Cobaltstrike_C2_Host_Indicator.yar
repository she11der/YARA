rule SIGNATURE_BASE_Cobaltstrike_C2_Host_Indicator : FILE
{
	meta:
		description = "Detects CobaltStrike C2 host artifacts"
		author = "yara@s3c.za.net"
		id = "7f15ee30-664e-59b8-9e31-35d88e58a45e"
		date = "2019-08-16"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cobaltstrike_evasive.yar#L1-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4761e282e9473ba665a597894ed514d057309703a7d5b4e462ef0e779bbb8c39"
		score = 60
		quality = 65
		tags = "FILE"

	strings:
		$c2_indicator_fp = "#Host: %s"
		$c2_indicator = "#Host:"

	condition:
		$c2_indicator and not $c2_indicator_fp and not uint32(0)==0x0a786564 and not uint32(0)==0x0a796564
}
