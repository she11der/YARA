rule SIGNATURE_BASE_CN_Honker_Oracle_V1_0_Oracle : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Oracle.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0cebede9-f4ff-5efb-98bc-55df0ad656a3"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L273-L289"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0264f4efdba09eaf1e681220ba96de8498ab3580"
		logic_hash = "6f1bb6b14445a9ca29768ab2dcf831a98cb5d153d03ebc4bc497bb8f8144a365"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "!http://localhost/index.asp?id=zhr" fullword ascii
		$s2 = "OnGetPassword" fullword ascii
		$s3 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3455KB and all of them
}
