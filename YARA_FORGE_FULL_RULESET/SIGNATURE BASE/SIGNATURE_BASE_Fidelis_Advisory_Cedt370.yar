rule SIGNATURE_BASE_Fidelis_Advisory_Cedt370
{
	meta:
		description = "Detects a string found in memory of malware cedt370r(3).exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b5ebf2d7-e3e4-5b3b-a082-417da9c7fda6"
		date = "2015-06-09"
		modified = "2023-12-05"
		reference = "http://goo.gl/ZjJyti"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fidelis_phishing_plain_sight.yar#L16-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1070d3c63a7091c0982e67134f9dc3cd790bb0b5c2ac08f3a00e3b97ef53d64b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "PO.exe" ascii fullword
		$s1 = "Important.exe" ascii fullword
		$s2 = "&username=" ascii fullword
		$s3 = "Browsers.txt" ascii fullword

	condition:
		all of them
}
