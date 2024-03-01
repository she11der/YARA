rule SIGNATURE_BASE_Icyfox007V1_10_Rar_Folder_Asp
{
	meta:
		description = "Webshells Auto-generated - file asp.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "52150b6a-2f60-5e6b-86d1-61bc0aeb4fa8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8781-L8792"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2c412400b146b7b98d6e7755f7159bb9"
		logic_hash = "3cc36668f0a2a6807b59c7da0b6e504b519a616ab63fb9f606eba5dc4a9e7e2f"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"

	condition:
		all of them
}
