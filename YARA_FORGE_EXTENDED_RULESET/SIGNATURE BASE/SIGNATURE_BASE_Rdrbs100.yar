rule SIGNATURE_BASE_Rdrbs100
{
	meta:
		description = "Webshells Auto-generated - file rdrbs100.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "369e5ce0-984c-54eb-96d4-fbfb4f932ba6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8170-L8182"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7c752bcd6da796d80a6830c61a632bff"
		logic_hash = "8a427ef9e0ecd0c810913203aaef43647964f33658dfdca8195fce6f0545f8f4"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "Server address must be IP in A.B.C.D format."
		$s4 = " mapped ports in the list. Currently "

	condition:
		all of them
}
