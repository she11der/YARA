rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Asp1 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp1.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "bf0b1f1e-cf7b-5afb-8e0a-bcfd70fc8887"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L1155-L1171"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "78b5889b363043ed8a60bed939744b4b19503552"
		logic_hash = "3b454b1254d05b2208aee02e966c9c56a338dd3d33a2c6acc2c4df3208314055"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "SItEuRl=" ascii
		$s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
		$s3 = "Server.ScriptTimeout=" ascii

	condition:
		filesize <200KB and all of them
}
