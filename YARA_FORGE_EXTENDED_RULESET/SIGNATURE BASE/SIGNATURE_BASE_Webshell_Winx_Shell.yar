rule SIGNATURE_BASE_Webshell_Winx_Shell
{
	meta:
		description = "Web Shell - file WinX Shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1632-L1646"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "17ab5086aef89d4951fe9b7c7a561dda"
		logic_hash = "e6dd5178cafccca751dd3f2e36206acd214a65b2e0783a738a104b3dc680ca21"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam"
		$s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </"

	condition:
		all of them
}
