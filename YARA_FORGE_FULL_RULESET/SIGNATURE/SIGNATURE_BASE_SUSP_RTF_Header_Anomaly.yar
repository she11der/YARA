rule SIGNATURE_BASE_SUSP_RTF_Header_Anomaly : FILE
{
	meta:
		description = "Detects malformed RTF header often used to trick mechanisms that check for a full RTF header"
		author = "Florian Roth (Nextron Systems)"
		id = "fb362640-9a45-5ee5-8749-3980e0549932"
		date = "2019-01-20"
		modified = "2022-09-15"
		reference = "https://twitter.com/ItsReallyNick/status/975705759618158593"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/generic_anomalies.yar#L494-L506"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c0be95894edc861cf322309f2c86a8ab986bb111dfdeea1990b4a074d5ab9ea3"
		score = 50
		quality = 85
		tags = "FILE"

	condition:
		uint32(0)==0x74725c7b and not uint8(4)==0x66
}
