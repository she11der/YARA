rule SIGNATURE_BASE__Crystal_Php_Nshell_Php_Php_Load_Shell_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "a92134cd-7f10-589f-bcda-508bc7a20efe"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L5381-L5396"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "71a9310b19b66e3699f75f551cc604f535ea843eb9c50f4a009edcd9c11e01b9"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "fdbf54d5bf3264eb1c4bff1fac548879"
		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
		hash2 = "0c5d227f4aa76785e4760cdcff78a661"

	strings:
		$s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
		$s1 = "$dires = $dires . $directory;" fullword
		$s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword

	condition:
		2 of them
}
