rule SIGNATURE_BASE_CN_Honker_Webshell_Cfm_Xl : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file xl.cfm"
		author = "Florian Roth (Nextron Systems)"
		id = "5c8d1301-fe20-50e0-86ac-99a220cd4be1"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L76-L91"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "49c3d16ee970945367a7d6ae86b7ade7cb3b5447"
		logic_hash = "b6683a24ad58a9444ec91f13e7da5db3e3e768afded09a23e1bbd0a0c23cf6b9"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<input name=\"DESTINATION\" value=\"" ascii
		$s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii

	condition:
		uint16(0)==0x433c and filesize <13KB and all of them
}
