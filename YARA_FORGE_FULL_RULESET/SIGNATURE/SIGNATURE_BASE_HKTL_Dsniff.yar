rule SIGNATURE_BASE_HKTL_Dsniff
{
	meta:
		description = "Detects Dsniff hack tool"
		author = "Florian Roth (Nextron Systems)"
		id = "eb39185b-330f-5b93-ac58-0465e5767919"
		date = "2019-02-19"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_sauron_extras.yar#L27-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0edd3ba7e78ee2810aa3c7643a96382c1fe0b5e627913a5a9bac2e83c8d40274"
		score = 55
		quality = 85
		tags = ""

	strings:
		$x1 = ".*account.*|.*acct.*|.*domain.*|.*login.*|.*member.*"

	condition:
		1 of them
}
