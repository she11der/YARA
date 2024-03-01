rule SIGNATURE_BASE_Rdrbs084
{
	meta:
		description = "Webshells Auto-generated - file rdrbs084.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "97548273-6894-5c9f-8cca-d966ce770ada"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7766-L7778"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ed30327b255816bdd7590bf891aa0020"
		logic_hash = "8a743d62723c4a5f863f986edd4b149728680b40d6a4b9a99b093d62ccb70cf8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Create mapped port. You have to specify domain when using HTTP type."
		$s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"

	condition:
		all of them
}
