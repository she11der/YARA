rule SIGNATURE_BASE_Injectionparameters : FILE
{
	meta:
		description = "Chinese Hacktool Set - file InjectionParameters.vb"
		author = "Florian Roth (Nextron Systems)"
		id = "a77bd0c6-8857-577f-831a-0fcf2537667e"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L53-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"
		logic_hash = "6bb786256f7154013408323eeb597f91c609a2a26f5ae9e6d61e16bd9c16a577"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
		$s1 = "Public Class InjectionParameters" fullword ascii

	condition:
		filesize <13KB and all of them
}
