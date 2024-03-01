rule SIGNATURE_BASE_Remsec_Executable_Blob_64
{
	meta:
		description = "Detects malware from Symantec's Strider APT report"
		author = "Symantec"
		id = "22345f40-3dae-5d5b-acc6-c67394475636"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_strider.yara#L22-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "957e5b6afabec3fb1b169dd85d0e950107e219f7dec8ef779a18bd90d9824a97"
		score = 80
		quality = 85
		tags = ""

	strings:
		$code = { 31 06 48 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 EF }

	condition:
		all of them
}
