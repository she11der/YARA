rule SIGNATURE_BASE_SUSP_WER_Critical_Heapcorruption : FILE
{
	meta:
		description = "Detects a crashed application that crashed due to a heap corruption error (could be a sign of exploitation)"
		author = "Florian Roth (Nextron Systems)"
		id = "2b1dad5f-cc2c-5d8c-8275-ebb56d079895"
		date = "2019-10-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1185459425710092288"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_wer_files.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "efa84e375f31ca37b9dd9c7a74251929ac957b9bd530e92f74b8836f56048fea"
		score = 45
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "ReportIdentifier=" wide
		$a2 = ".Name=Fault Module Name" wide
		$s1 = "c0000374" wide

	condition:
		( uint32be(0)==0x56006500 or uint32be(0)==0xfffe5600) and all of them
}
