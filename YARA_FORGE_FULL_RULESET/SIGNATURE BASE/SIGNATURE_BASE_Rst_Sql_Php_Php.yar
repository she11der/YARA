rule SIGNATURE_BASE_Rst_Sql_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file rst_sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "41730336-0dce-5ed9-95b0-c911a4e3cb48"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3859-L3872"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0961641a4ab2b8cb4d2beca593a92010"
		logic_hash = "d15cf69d9ad8683d2ac1ff09b08b0b26ecaf35df8e45bbd5c3a02c393f88cb34"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "C:\\tmp\\dump_"
		$s1 = "RST MySQL"
		$s2 = "http://rst.void.ru"
		$s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';"

	condition:
		2 of them
}
