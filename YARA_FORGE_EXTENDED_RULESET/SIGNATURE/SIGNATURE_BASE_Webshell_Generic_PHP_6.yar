rule SIGNATURE_BASE_Webshell_Generic_PHP_6
{
	meta:
		description = "PHP Webshells Github Archive"
		author = "Florian Roth (Nextron Systems)"
		id = "e61ec617-565a-5b24-82f4-3677ef379a06"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7098-L7119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7b3f2ca3cb9516ddda1b9cac2ca5eb5d9e62e1839dad041f69a3dc7a2a186897"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "1a08f5260c4a2614636dfc108091927799776b13"
		hash1 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash2 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"

	strings:
		$s2 = "@eval(stripslashes($_POST['phpcode']));" fullword
		$s5 = "echo shell_exec($com);" fullword
		$s7 = "if($sertype == \"winda\"){" fullword
		$s8 = "function execute($com)" fullword
		$s12 = "echo decode(execute($cmd));" fullword
		$s15 = "echo system($com);" fullword

	condition:
		4 of them
}
