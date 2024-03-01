rule SIGNATURE_BASE_SUSP_Piratedoffice_2007 : FILE
{
	meta:
		description = "Detects an Office document that was created with a pirated version of MS Office 2007"
		author = "Florian Roth (Nextron Systems)"
		id = "b36e9a59-7617-503b-968d-5b6b72b227ea"
		date = "2018-12-04"
		modified = "2023-12-05"
		reference = "https://twitter.com/pwnallthethings/status/743230570440826886?lang=en"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/generic_anomalies.yar#L409-L422"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ff94483944a4a4e4bc3cba26fc08fc2a5239f27b301b2ca7cca5edc092c2fc73"
		score = 40
		quality = 85
		tags = "FILE"
		hash1 = "210448e58a50da22c0031f016ed1554856ed8abe79ea07193dc8f5599343f633"

	strings:
		$s7 = "<Company>Grizli777</Company>" ascii

	condition:
		uint16(0)==0xcfd0 and filesize <300KB and all of them
}
