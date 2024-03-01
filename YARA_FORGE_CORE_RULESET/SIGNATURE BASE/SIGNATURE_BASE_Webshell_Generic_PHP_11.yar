rule SIGNATURE_BASE_Webshell_Generic_PHP_11
{
	meta:
		description = "PHP Webshells Github Archive - from files rootshell.php, Rootshell.v.1.0.php, s72 Shell v1.1 Coding.php, s72_Shell_v1.1_Coding.php"
		author = "Florian Roth (Nextron Systems)"
		id = "590c5320-ef85-5522-94fd-4619749f7eb1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7060-L7082"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "5a559a26314ce603d6454efb71f1243bf89daed920ca2a495a51b94a4cca0045"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "31a82cbee8dffaf8eb7b73841f3f3e8e9b3e78cf"
		hash1 = "838c7191cb10d5bb0fc7460b4ad0c18c326764c6"
		hash2 = "8dfcd919d8ddc89335307a7b2d5d467b1fd67351"
		hash3 = "80aba3348434c66ac471daab949871ab16c50042"

	strings:
		$s5 = "$filename = $backupstring.\"$filename\";" fullword
		$s6 = "while ($file = readdir($folder)) {" fullword
		$s7 = "if($file != \".\" && $file != \"..\")" fullword
		$s9 = "$backupstring = \"copy_of_\";" fullword
		$s10 = "if( file_exists($file_name))" fullword
		$s13 = "global $file_name, $filename;" fullword
		$s16 = "copy($file,\"$filename\");" fullword
		$s18 = "<td width=\"49%\" height=\"142\">" fullword

	condition:
		all of them
}
