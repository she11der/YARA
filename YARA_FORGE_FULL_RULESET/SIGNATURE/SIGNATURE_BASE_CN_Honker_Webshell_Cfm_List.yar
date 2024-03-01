rule SIGNATURE_BASE_CN_Honker_Webshell_Cfm_List : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file list.cfm"
		author = "Florian Roth (Nextron Systems)"
		id = "98302eef-d1e8-5524-a57e-d49c0e92c7e0"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L459-L474"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "85d445b13d2aef1df3b264c9b66d73f0ff345cec"
		logic_hash = "41c7c5ba6187a8871dec83bcd859b9377813d60cea8ef2b4ad390c67de04e010"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii
		$s2 = "<TD>#mydirectory.size#</TD>" fullword ascii

	condition:
		filesize <10KB and all of them
}
