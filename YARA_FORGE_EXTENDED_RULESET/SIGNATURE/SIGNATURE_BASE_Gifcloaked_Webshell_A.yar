import "pe"
import "math"

rule SIGNATURE_BASE_Gifcloaked_Webshell_A : FILE
{
	meta:
		description = "Looks like a webshell cloaked as GIF"
		author = "Florian Roth (Nextron Systems)"
		id = "4fdef65c-204a-5019-9b4f-c5877c3e39d4"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/yara_mixed_ext_vars.yar#L180-L201"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
		logic_hash = "0c4570373d50c40745cd0523dcf8c34ee3cae1c298982b3a39d4a33e054aa779"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "input type"
		$s1 = "<%eval request"
		$s2 = "<%eval(Request.Item["
		$s3 = "LANGUAGE='VBScript'"
		$s4 = "$_REQUEST" fullword
		$s5 = ";eval("
		$s6 = "base64_decode"
		$fp1 = "<form name=\"social_form\""

	condition:
		uint32(0)==0x38464947 and (1 of ($s*)) and not 1 of ($fp*)
}
