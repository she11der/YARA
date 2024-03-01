rule SIGNATURE_BASE_Webshell_Elmaliseker_2
{
	meta:
		description = "Web Shell - file elmaliseker.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L857-L871"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
		logic_hash = "ca300cd142b3c8b820d3b5f5a56eeb834d9acb1d85916b932bd67fb4a25f4ed0"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
		$s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"

	condition:
		all of them
}
