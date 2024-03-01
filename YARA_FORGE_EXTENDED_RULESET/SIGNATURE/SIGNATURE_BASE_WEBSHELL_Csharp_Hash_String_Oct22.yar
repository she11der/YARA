rule SIGNATURE_BASE_WEBSHELL_Csharp_Hash_String_Oct22 : FILE
{
	meta:
		description = "C# webshell using specific hash check for the password."
		author = "Nils Kuhnert (modified by Florian Roth)"
		id = "c7d459be-5e61-57b7-b738-051c0cec62d2"
		date = "2022-10-27"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_webshell_csharp.yar#L2-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "29c187ad46d3059dc25d5f0958e0e8789fb2a51b9daaf90ea27f001b1a9a603c"
		logic_hash = "28a07f3dd17fc469388867fa82a0e21abeee9c4e114af245b684535e4e194891"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$gen1 = "void Page_Load" ascii
		$gen2 = "FromBase64String" ascii
		$gen3 = "CryptoServiceProvider" ascii
		$gen4 = "ComputeHash" ascii
		$hashing1 = "BitConverter.ToString(" ascii
		$hashing2 = ").Replace(\"-\", \"\") == \"" ascii
		$filter1 = "BitConverter.ToString((" ascii

	condition:
		filesize <10KB and all of ($gen*) and all of ($hashing*) and not 1 of ($filter*)
}
