import "pe"

rule SIGNATURE_BASE_Mimikatz_Memory_Rule_1 : APT
{
	meta:
		description = "Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)"
		author = "Florian Roth"
		id = "55cc7129-5ea0-5545-a8f6-b5306a014dd0"
		date = "2014-12-22"
		modified = "2023-07-04"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mimikatz.yar#L5-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "22064af570b8e0a93ca0d45484848eda3fbecfd27c88247ef0897fe53be4b7fc"
		score = 70
		quality = 85
		tags = ""
		nodeepdive = 1

	strings:
		$s1 = "sekurlsa::wdigest" fullword ascii
		$s2 = "sekurlsa::logonPasswords" fullword ascii
		$s3 = "sekurlsa::minidump" fullword ascii
		$s4 = "sekurlsa::credman" fullword ascii
		$fp1 = "\"x_mitre_version\": " ascii
		$fp2 = "{\"type\":\"bundle\","
		$fp3 = "use strict" ascii fullword
		$fp4 = "\"url\":\"https://attack.mitre.org/" ascii

	condition:
		1 of ($s*) and not 1 of ($fp*)
}
