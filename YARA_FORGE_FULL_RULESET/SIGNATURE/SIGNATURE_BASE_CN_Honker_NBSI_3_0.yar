rule SIGNATURE_BASE_CN_Honker_NBSI_3_0 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file NBSI 3.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "be8d0dce-4f7f-5f18-9ed0-99fc1dc2b22f"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1664-L1681"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "93bf0f64bec926e9aa2caf4c28df9af27ec0e104"
		logic_hash = "017b5f76a3168089f3186134e7a4c0352158bb866228776240f0d014834e6ee0"
		score = 70
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide
		$s2 = "http://localhost/1.asp?id=16" fullword ascii
		$s3 = " exec master.dbo.xp_cmdshell @Z--" fullword wide
		$s4 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide

	condition:
		uint16(0)==0x5a4d and filesize <2600KB and 2 of them
}
