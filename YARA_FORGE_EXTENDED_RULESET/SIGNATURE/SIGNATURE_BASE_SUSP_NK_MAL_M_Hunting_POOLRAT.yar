import "pe"

rule SIGNATURE_BASE_SUSP_NK_MAL_M_Hunting_POOLRAT
{
	meta:
		description = "Detects strings found in POOLRAT malware"
		author = "Mandiant"
		id = "70f5f3a0-0fd0-54dc-97cc-4f3c35f02fcd"
		date = "2023-04-20"
		modified = "2023-12-05"
		old_rule_name = "APT_NK_MAL_M_Hunting_POOLRAT"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_nk_tradingtech_apr23.yar#L166-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ac8db844a9c4ed961930417809afb706ea948c4509a4be1eaeed77f09c86069d"
		score = 70
		quality = 83
		tags = ""
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "451c23709ecd5a8461ad060f6346930c"

	strings:
		$s1 = "name=\"uid\"%s%s%u%s" ascii wide
		$s2 = "name=\"session\"%s%s%u%s" ascii wide
		$s3 = "name=\"action\"%s%s%s%s" ascii wide
		$s4 = "name=\"token\"%s%s%u%s" ascii wide
		$str1 = "--N9dLfqxHNUUw8qaUPqggVTpX-" wide ascii nocase

	condition:
		any of ($s*) or $str1
}
