rule SIGNATURE_BASE_Webshell_Simple_Cmd
{
	meta:
		description = "PHP Webshells Github Archive - file simple_cmd.php"
		author = "Florian Roth (Nextron Systems)"
		id = "1fd0c01a-c265-5e30-ab36-e8e93e316fbe"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6617-L6631"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "466a8caf03cdebe07aa16ad490e54744f82e32c2"
		logic_hash = "82a65f4bbdcd2fc626aa9f36fe530d19aa19a48389e970c26e525597818914ee"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s2 = "<title>G-Security Webshell</title>" fullword
		$s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword

	condition:
		1 of them
}
