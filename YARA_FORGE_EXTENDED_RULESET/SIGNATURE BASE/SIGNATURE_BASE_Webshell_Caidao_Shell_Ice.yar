rule SIGNATURE_BASE_Webshell_Caidao_Shell_Ice
{
	meta:
		description = "Web Shell - file ice.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L276-L289"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "6560b436d3d3bb75e2ef3f032151d139"
		logic_hash = "d92cc9ac8630b40f23b9ff7cda5a237b4885d30de4b9b497be7512e7eb020a09"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%eval request(\"ice\")%>" fullword

	condition:
		all of them
}
