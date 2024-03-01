import "pe"

rule SIGNATURE_BASE_CN_Portscan : APT FILE
{
	meta:
		description = "CN Port Scanner"
		author = "Florian Roth (Nextron Systems)"
		id = "fb52a89a-2270-5170-9874-9278a0177454"
		date = "2013-11-29"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2927-L2941"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e1b745bd321527cee3eb203847d00c9eda4a7b1e498cb8f0ad6b588f87221759"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		confidential = false

	strings:
		$s2 = "TCP 12.12.12.12"

	condition:
		uint16(0)==0x5A4D and $s2
}
