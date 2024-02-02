rule SIGNATURE_BASE_HKTL_Cobaltstrike_Beacon_Strings
{
	meta:
		description = "Identifies strings used in Cobalt Strike Beacon DLL"
		author = "Elastic"
		id = "af558aa2-a3dc-5a7a-bc74-42bb2246091c"
		date = "2021-03-16"
		modified = "2023-12-05"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_cobaltstrike.yar#L54-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4349a7ad94df2269217b55c2aef9628c4eef078566c276936accdd4f996ba2cf"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "%02d/%02d/%02d %02d:%02d:%02d"
		$s2 = "Started service %s on %s"
		$s3 = "%s as %s\\%s: %d"

	condition:
		2 of them
}