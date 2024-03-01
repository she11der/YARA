rule SIGNATURE_BASE_Obfuscated_JS_April17 : FILE
{
	meta:
		description = "Detects cloaked Mimikatz in JS obfuscation"
		author = "Florian Roth (Nextron Systems)"
		id = "44abd2c0-5f8d-5a8c-b282-a09853e12054"
		date = "2017-04-21"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/general_cloaking.yar#L139-L153"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c75bf0ad8dd35fabbaedb54c2630249497edbb215b6ce2b707e32f82e8fb8f56"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\";function Main(){for(var " ascii
		$s2 = "=String.fromCharCode(parseInt(" ascii
		$s3 = "));(new Function(" ascii

	condition:
		filesize <500KB and all of them
}
