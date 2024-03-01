rule SIGNATURE_BASE_Webshell_Asp_1D
{
	meta:
		description = "Web Shell - file 1d.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1350-L1363"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "fad7504ca8a55d4453e552621f81563c"
		logic_hash = "85b17fde8fb535b64e5eabc887428d9b73adc5bc6741a3a387f235a8b0c6089a"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"

	condition:
		all of them
}
