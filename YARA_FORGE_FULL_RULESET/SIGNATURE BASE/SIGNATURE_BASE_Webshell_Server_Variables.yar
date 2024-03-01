rule SIGNATURE_BASE_Webshell_Server_Variables
{
	meta:
		description = "Web Shell - file Server Variables.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L434-L448"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "47fb8a647e441488b30f92b4d39003d7"
		logic_hash = "2a85301f1d6e4c457ff0a1b2a08eb6f054905993a0667087f37b9a7352e38911"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
		$s9 = "Variable Name</B></font></p>" fullword

	condition:
		all of them
}
