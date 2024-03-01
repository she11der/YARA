rule SIGNATURE_BASE_CN_Honker_Baidu_Extractor_Ver1_0 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Baidu_Extractor_Ver1.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "94f3c3d8-aa68-5589-b26f-42315634ff30"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1025-L1042"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1899f979360e96245d31082e7e96ccedbdbe1413"
		logic_hash = "cba7357ab3cb840b3b115abe00e1a3a712feb036cae816c8ded10d73029efe2b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "\\Users\\Admin" wide
		$s11 = "soso.com" fullword wide
		$s12 = "baidu.com" fullword wide
		$s19 = "cmd /c ping " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
