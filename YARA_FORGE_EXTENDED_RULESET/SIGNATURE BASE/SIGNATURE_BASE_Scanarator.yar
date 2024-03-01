import "pe"

rule SIGNATURE_BASE_Scanarator
{
	meta:
		description = "Auto-generated rule on file scanarator.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "dfc3ff29-03b4-58ca-bfe0-c6888fddab67"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L302-L312"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "848bd5a518e0b6c05bd29aceb8536c46"
		logic_hash = "9400435470c26245cd814e1e39f275eb22566d66d1a72d4f3e618a6ad11bc8d9"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"

	condition:
		all of them
}
