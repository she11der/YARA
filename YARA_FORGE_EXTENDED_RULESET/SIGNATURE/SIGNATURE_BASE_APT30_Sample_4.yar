rule SIGNATURE_BASE_APT30_Sample_4 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "e5c6afde-0ab5-54ed-8d18-5ad477a527d7"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L90-L108"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "75367d8b506031df5923c2d8d7f1b9f643a123cd"
		logic_hash = "ec9542acb583bd5812d561bea70e89e0fcddc1eaef14d3ea5b8ad29711ed17ae"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "GetStartupIn" ascii
		$s1 = "enMutex" ascii
		$s2 = "tpsvimi" ascii
		$s3 = "reateProcesy" ascii
		$s5 = "FreeLibr1y*S" ascii
		$s6 = "foAModuleHand" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
