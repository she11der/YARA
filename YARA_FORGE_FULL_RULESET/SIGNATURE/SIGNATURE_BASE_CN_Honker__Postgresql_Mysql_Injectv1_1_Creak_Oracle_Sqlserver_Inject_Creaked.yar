rule SIGNATURE_BASE_CN_Honker__Postgresql_Mysql_Injectv1_1_Creak_Oracle_Sqlserver_Inject_Creaked : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset"
		author = "Florian Roth (Nextron Systems)"
		id = "0272776c-8dbe-5345-92c8-57593686a84c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2358-L2378"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ed809a5fb35d36b2a8758e470657bda1a04d80577d5129962cd7d0ab9a80cf8a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "1ecfaa91aae579cfccb8b7a8607176c82ec726f4"
		hash1 = "a1f066789f48a76023598c5777752c15f91b76b0"
		hash2 = "0264f4efdba09eaf1e681220ba96de8498ab3580"
		hash3 = "af3c41756ec8768483a4cf59b2e639994426e2c2"

	strings:
		$s1 = "zhaoxypass@yahoo.com.cn" fullword ascii
		$s2 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
		$s3 = "ProxyParams.ProxyPort" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
