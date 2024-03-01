rule SIGNATURE_BASE_CN_Honker_Ms11080_Withcmd : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11080_withcmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "38c12697-7e52-5713-a566-6047abfa229b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1175-L1190"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
		logic_hash = "1f673f845ad40efae143ec244c7c70d1e26fb51f22be6bf445085c6a7379f193"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s3 = "[>] create pipe error" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <340KB and all of them
}
