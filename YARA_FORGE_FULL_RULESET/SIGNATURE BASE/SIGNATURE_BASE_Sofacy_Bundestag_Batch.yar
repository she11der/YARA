import "pe"

rule SIGNATURE_BASE_Sofacy_Bundestag_Batch : FILE
{
	meta:
		description = "Sofacy Bundestags APT Batch Script"
		author = "Florian Roth (Nextron Systems)"
		id = "869dafec-1387-5640-b608-b84cf0d43342"
		date = "2015-06-19"
		modified = "2023-12-05"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sofacy_xtunnel_bundestag.yar#L101-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "05d6df161042a65f9eeec4be4046001a03fa61747a9ea123f13e6e75d6664ac7"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx)" ascii
		$s2 = "cmd /c copy"
		$s3 = "forfiles"

	condition:
		filesize <10KB and 2 of them
}
