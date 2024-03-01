rule SIGNATURE_BASE_Myshell_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file myshell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "eaf243cb-fa26-5f34-a724-60a08acff636"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4238-L4250"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "62783d1db52d05b1b6ae2403a7044490"
		logic_hash = "dd7b0fa637a8317986de0c2312b4b552f1110fb5a64590a9a21c854e5985fbb6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory."
		$s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color"
		$s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$"

	condition:
		2 of them
}
