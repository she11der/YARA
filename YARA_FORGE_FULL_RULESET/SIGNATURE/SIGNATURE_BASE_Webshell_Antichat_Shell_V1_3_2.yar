rule SIGNATURE_BASE_Webshell_Antichat_Shell_V1_3_2
{
	meta:
		description = "Web Shell - file Antichat Shell v1.3.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1482-L1495"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "40d0abceba125868be7f3f990f031521"
		logic_hash = "d5a1dc31f442f8db7771ee64164436f6c562ef9f4a203a1e2006d37f9df91846"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"

	condition:
		all of them
}
