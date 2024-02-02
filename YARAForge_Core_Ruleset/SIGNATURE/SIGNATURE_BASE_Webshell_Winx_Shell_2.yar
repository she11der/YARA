rule SIGNATURE_BASE_Webshell_Winx_Shell_2
{
	meta:
		description = "PHP Webshells Github Archive - file WinX Shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "ebad4f2e-96c3-5cb7-b228-de3a6a39ae55"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "WebShell_WinX_Shell"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6481-L6497"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "a94d65c168344ad9fa406d219bdf60150c02010e"
		logic_hash = "f953c297763e41d197ce186dc818b656951dfa8c855c5063fc4abb54eeefc7bb"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "// It's simple shell for all Win OS." fullword
		$s5 = "//------- [netstat -an] and [ipconfig] and [tasklist] ------------" fullword
		$s6 = "<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>" fullword
		$s13 = "// Created by greenwood from n57" fullword
		$s20 = " if (is_uploaded_file($userfile)) {" fullword

	condition:
		3 of them
}