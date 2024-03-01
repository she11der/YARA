rule SIGNATURE_BASE_Nanocore_RAT_Sample_2 : FILE
{
	meta:
		description = "Detetcs a certain Nanocore RAT sample"
		author = "Florian Roth (Nextron Systems)"
		id = "81f6771a-29a3-5fa0-8d24-ea717d3c5251"
		date = "2016-04-22"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_nanocore_rat.yar#L64-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "505176b7320e95c652f0b6fdc6fadc3d16ff30115263862ba61209fa2fb82a2d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"

	strings:
		$s1 = "U4tSOtmpM" fullword ascii
		$s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" wide
		$s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and all of ($s*)
}
