rule SIGNATURE_BASE_CN_Honker_Struts2_Catbox : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file catbox.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "24df7a11-5ec4-5e7b-86f6-6195ca01b8f9"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L792-L807"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ee8fbd91477e056aef34fce3ade474cafa1a4304"
		logic_hash = "20bda5c918ea38810603528a20f3406ec4e79ce999681649e8e806bf549b5359"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "'Toolmao box by gainover www.toolmao.com" fullword ascii
		$s20 = "{external.exeScript(_toolmao_bgscript[i],'javascript',false);}}" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <8160KB and all of them
}
