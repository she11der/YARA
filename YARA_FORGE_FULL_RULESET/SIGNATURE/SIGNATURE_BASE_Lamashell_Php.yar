rule SIGNATURE_BASE_Lamashell_Php
{
	meta:
		description = "Semi-Auto-generated  - file lamashell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "cbbb3377-ef9c-5fd1-a8b8-2b730fb5ef28"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4574-L4586"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "de9abc2e38420cad729648e93dfc6687"
		logic_hash = "5e156c3057338fa7b306b91dd979851dd56b8b698cfe99e1d7b6d096a4c580e7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "lama's'hell" fullword
		$s1 = "if($_POST['king'] == \"\") {"
		$s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f"

	condition:
		1 of them
}
