rule SIGNATURE_BASE_HTA_Embedded
{
	meta:
		description = "Detects an embedded HTA file"
		author = "Florian Roth (Nextron Systems)"
		id = "04d4c718-9dd6-5528-8712-61c9f2a16139"
		date = "2017-06-21"
		modified = "2023-12-05"
		reference = "https://twitter.com/msftmmpc/status/877396932758560768"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_hta_anomalies.yar#L28-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "843f0ad5e39e5492db8ff7372f6d2038e7dbb7823ec9b33f863ab891a108b1ec"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"

	strings:
		$s1 = "<hta:application windowstate=\"minimize\"/>"

	condition:
		$s1 and not $s1 in (0..50000)
}
