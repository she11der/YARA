rule SIGNATURE_BASE_Hawkeye_PHP_Panel : FILE
{
	meta:
		description = "Detects HawkEye Keyloggers PHP Panel"
		author = "Florian Roth (Nextron Systems)"
		id = "1d185345-6684-538f-954a-45d57a618a7a"
		date = "2014-12-14"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9115-L9130"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e29b6df4e3aa3892b10e68218320ac76cecb5a1bbe6c48f2276014b972cbbdd8"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$fname = $_GET['fname'];" ascii fullword
		$s1 = "$data = $_GET['data'];" ascii fullword
		$s2 = "unlink($fname);" ascii fullword
		$s3 = "echo \"Success\";" fullword ascii

	condition:
		all of ($s*) and filesize <600
}
