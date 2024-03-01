rule SIGNATURE_BASE_SUSP_Obfuscated_JS_Obfuscatorio : HIGHVOL FILE
{
	meta:
		description = "Detects JS obfuscation done by the js obfuscator (often malicious)"
		author = "@imp0rtp3"
		id = "d808f96c-21c9-59c7-b3c7-f118d39d564e"
		date = "2021-08-25"
		modified = "2023-12-05"
		reference = "https://obfuscator.io"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_js_obfuscatorio.yar#L1-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "813df8459e4a53a084dc1f902713af74747a0c2f4ef535e682de38acba9b0e5e"
		score = 50
		quality = 35
		tags = "FILE"

	strings:
		$a1 = "var a0_0x"
		$c1 = "))),function(){try{var _0x"
		$c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$c3 = "['atob']=function("
		$c4 = ")['replace'](/=+$/,'');var"
		$c5 = "return!![]"
		$c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'"
		$c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64
		$c8 = "while(!![])"
		$c9 = "while (!![])"
		$d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/

	condition:
		$a1 at 0 or ( filesize <1000000 and (3 of ($c*) or $d1))
}
