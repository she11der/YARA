rule SIGNATURE_BASE_SUSP_Double_Base64_Encoded_Executable
{
	meta:
		description = "Detects an executable that has been encoded with base64 twice"
		author = "Florian Roth (Nextron Systems)"
		id = "6fb40ed3-1afc-5d5b-9373-4a8490177b20"
		date = "2019-10-29"
		modified = "2023-12-05"
		reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_susp_obfuscation.yar#L19-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ac739ed2af7dff70d7a05e661582a8fdd618e77aa5e0e0f42d6ea314265a129c"
		score = 65
		quality = 85
		tags = ""
		hash1 = "1a172d92638e6fdb2858dcca7a78d4b03c424b7f14be75c2fd479f59049bc5f9"

	strings:
		$ = "VFZwVEFRR" ascii wide
		$ = "RWcFRBUU" ascii wide
		$ = "UVnBUQVFF" ascii wide
		$ = "VFZvQUFBQ" ascii wide
		$ = "RWb0FBQU" ascii wide
		$ = "UVm9BQUFB" ascii wide
		$ = "VFZxQUFBR" ascii wide
		$ = "RWcUFBQU" ascii wide
		$ = "UVnFBQUFF" ascii wide
		$ = "VFZwUUFBS" ascii wide
		$ = "RWcFFBQU" ascii wide
		$ = "UVnBRQUFJ" ascii wide
		$ = "VFZxUUFBT" ascii wide
		$ = "RWcVFBQU" ascii wide
		$ = "UVnFRQUFN" ascii wide

	condition:
		1 of them
}
