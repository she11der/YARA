rule SIGNATURE_BASE_CN_Honker_Webshell_Mycode12 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mycode12.cfm"
		author = "Florian Roth (Nextron Systems)"
		id = "2ce7368c-7565-5b32-94d1-c87023404c5b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L42-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "64be8760be5ab5c2dcf829e3f87d3e50b1922f17"
		logic_hash = "94cb0e414634af753db9ec0c63a3a34b4f9104e93e01d67cebab7b3a0c471198"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii
		$s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii

	condition:
		filesize <4KB and all of them
}
