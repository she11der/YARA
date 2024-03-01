import "pe"

rule SIGNATURE_BASE_Msbuild_Mimikatz_Execution_Via_XML
{
	meta:
		description = "Detects an XML that executes Mimikatz on an endpoint via MSBuild"
		author = "Florian Roth (Nextron Systems)"
		id = "98aa68b9-6de4-5353-8d87-9e974529c044"
		date = "2016-10-07"
		modified = "2023-12-05"
		reference = "https://gist.github.com/subTee/c98f7d005683e616560bda3286b6a0d8#file-katz-xml"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3417-L3436"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f926a2d5ab987b97c6ed2a89c69eac5549d8b7885bdbf75ce40e05e6ce6cfa7a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "<Project ToolsVersion=" ascii
		$x2 = "</SharpLauncher>" fullword ascii
		$s1 = "\"TVqQAAMAAAA" ascii
		$s2 = "System.Convert.FromBase64String(" ascii
		$s3 = ".Invoke(" ascii
		$s4 = "Assembly.Load(" ascii
		$s5 = ".CreateInstance(" ascii

	condition:
		all of them
}
